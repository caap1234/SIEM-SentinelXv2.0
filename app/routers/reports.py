from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import ALGORITHM
from app.db import get_db
from app.models.report import Report
from app.models.user import User
from app.routers.auth import get_current_user
from app.services.reporting_service import ReportingService

router = APIRouter(prefix="/reports", tags=["Reports"])


def get_current_user_from_token_or_header(
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Optional[User]:
    auth_header = request.headers.get("Authorization")
    raw_token = None
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ", 1)[1]
    elif token:
        raw_token = token

    if not raw_token:
        return None

    try:
        payload = jwt.decode(raw_token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id:
            return db.query(User).filter(User.id == int(user_id)).first()
    except Exception:
        pass
    return None


class GenerateReportRequest(BaseModel):
    type: str = Field(..., description="executive_weekly, executive_monthly, executive_quarterly, soc_operational, trends, incident_report")
    format: str = Field("pdf", description="pdf, html, json, csv")
    days: int = Field(7, ge=1, le=365)
    incident_id: Optional[int] = None
    server: Optional[str] = None
    severity: Optional[str] = None


class ReportDTO(BaseModel):
    id: int
    tenant_id: str
    type: str
    created_by: str
    created_at: datetime
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    format: str
    storage_path: Optional[str] = None
    status: str
    meta: Dict[str, Any] = {}

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    total: int
    items: List[ReportDTO]


@router.get("", response_model=ReportListResponse)
def list_reports(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportListResponse:
    """Listar metadatos de reportes históricos filtrados por el tenant_id del usuario."""
    tenant_id = getattr(current_user, "tenant_id", "default") or "default"
    q = db.query(Report).filter(Report.tenant_id == tenant_id).order_by(Report.created_at.desc())
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return ReportListResponse(total=total, items=[ReportDTO.model_validate(r) for r in items])


@router.post("/generate", response_model=ReportDTO, status_code=201)
def generate_report_endpoint(
    payload: GenerateReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportDTO:
    """Generar un nuevo reporte SOC con datos reales y guardar el binario en almacenamiento S3/local."""
    tenant_id = getattr(current_user, "tenant_id", "default") or "default"
    created_by = getattr(current_user, "email", "system") or "system"

    service = ReportingService(db, tenant_id=tenant_id, created_by=created_by)
    try:
        report = service.generate_report(
            report_type=payload.type,
            fmt=payload.format,
            days=payload.days,
            incident_id=payload.incident_id,
        )
        return ReportDTO.model_validate(report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte: {e}")


@router.get("/{report_id}", response_model=ReportDTO)
def get_report_metadata(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportDTO:
    """Obtener metadatos de un reporte específico."""
    tenant_id = getattr(current_user, "tenant_id", "default") or "default"
    report = db.query(Report).filter(Report.id == report_id, Report.tenant_id == tenant_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado o sin acceso")
    return ReportDTO.model_validate(report)


@router.get("/{report_id}/download")
def download_report_file(
    report_id: int,
    request: Request,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Descargar el archivo generado (PDF, HTML, JSON, CSV) de un reporte."""
    user = get_current_user_from_token_or_header(request, token, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    tenant_id = getattr(user, "tenant_id", "default") or "default"
    report = db.query(Report).filter(Report.id == report_id, Report.tenant_id == tenant_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    local_path = report.meta.get("local_file_path") if isinstance(report.meta, dict) else None
    if not local_path or not os.path.isfile(local_path):
        raise HTTPException(status_code=404, detail="Archivo binario de reporte no disponible en almacenamiento")

    media_type = "application/pdf" if report.format == "pdf" else "text/html"
    if report.format == "json":
        media_type = "application/json"
    elif report.format == "csv":
        media_type = "text/csv"

    headers = {
        "Content-Disposition": f'inline; filename="sentinelx_report_{report.type}_{report.id}.{report.format}"'
    }

    return FileResponse(
        path=local_path,
        media_type=media_type,
        headers=headers,
    )


@router.get("/incident/{incident_id}")
def generate_incident_report_dossier(
    incident_id: int,
    request: Request,
    fmt: str = Query("html", description="html o pdf"),
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Generar o visualizar expediente forense individual de un incidente."""
    user = get_current_user_from_token_or_header(request, token, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    tenant_id = getattr(user, "tenant_id", "default") or "default"
    created_by = getattr(user, "email", "system") or "system"

    service = ReportingService(db, tenant_id=tenant_id, created_by=created_by)
    try:
        report = service.generate_report("incident_report", fmt=fmt, incident_id=incident_id)
        local_path = report.meta.get("local_file_path")
        if fmt == "html" and local_path and os.path.isfile(local_path):
            with open(local_path, "r", encoding="utf-8") as f:
                content = f.read()
            return HTMLResponse(content=content)
        return ReportDTO.model_validate(report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando dossier de incidente: {e}")

