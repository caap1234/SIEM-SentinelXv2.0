# app/routers/lists.py
"""
API Router para la gestión centralizada de Listas de Seguridad (Security Lists).
Permite administrar Whitelists, Blacklists, Excepciones por regla, Listas de referencia y BlacklistMaster.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.security_list import (
    SecurityListAudit,
    SecurityListEntry,
    SecurityListIgnoreLog,
)
from app.schemas.dependencies import AuthContext, require_permission
from app.services.security_list_service import SecurityListService

router = APIRouter(prefix="/api/v1/lists", tags=["security_lists"])


# =========================================================================
# SCHEMAS PYDANTIC
# =========================================================================

class CreateListEntrySchema(BaseModel):
    tenant_id: str = Field(default="global", description="ID de tenant o 'global'")
    list_type: str = Field(..., description="Tipo de lista (whitelist_ip, exception_rule, list_ref, blm_ignore, etc.)")
    value: str = Field(..., description="Valor almacenado (IP, CIDR, ASN, país, token, etc.)")
    value_type: str = Field(default="ip", description="Tipo de valor: ip, cidr, asn, country_code, token, username, server")
    list_name: Optional[str] = Field(default=None, description="Nombre de lista para list_ref (ej: privileged_users)")
    rule_code: Optional[str] = Field(default=None, description="Código de regla para excepción específica (ej: AUTH-006)")
    reason: Optional[str] = Field(default=None, description="Motivo de creación / referencia")
    enabled: bool = Field(default=True, description="Estado activo / inactivo")
    expires_at: Optional[str] = Field(default=None, description="Fecha de expiración ISO 8601 (opcional)")


class UpdateListEntrySchema(BaseModel):
    tenant_id: Optional[str] = None
    list_type: Optional[str] = None
    value: Optional[str] = None
    value_type: Optional[str] = None
    list_name: Optional[str] = None
    rule_code: Optional[str] = None
    reason: Optional[str] = None
    enabled: Optional[bool] = None
    expires_at: Optional[str] = None


class ToggleSchema(BaseModel):
    enabled: Optional[bool] = None


# =========================================================================
# ENDPOINTS API REST
# =========================================================================

@router.get("/types")
def get_list_types(
    ctx: AuthContext = Depends(require_permission("system.read")),
) -> Dict[str, Any]:
    """Catálogo de tipos de listas soportadas y sus metadatos."""
    return {
        "types": [
            {"type": "whitelist_ip", "label": "Whitelist IP", "value_type": "ip", "group": "whitelist"},
            {"type": "whitelist_cidr", "label": "Whitelist CIDR", "value_type": "cidr", "group": "whitelist"},
            {"type": "trusted_country", "label": "País Confiable", "value_type": "country_code", "group": "whitelist"},
            {"type": "trusted_asn", "label": "ASN Confiable", "value_type": "asn", "group": "whitelist"},
            {"type": "trusted_server", "label": "Servidor Confiable", "value_type": "ip", "group": "whitelist"},
            {"type": "exception_rule", "label": "Excepción por Regla", "value_type": "ip", "group": "exception"},
            {"type": "list_ref", "label": "Lista de Referencia", "value_type": "token", "group": "reference"},
            {"type": "blm_ignore", "label": "BlacklistMaster — Ignorar", "value_type": "ip", "group": "blacklistmaster"},
            {"type": "blm_shared", "label": "BlacklistMaster — Shared Hosting", "value_type": "ip", "group": "blacklistmaster"},
            {"type": "blm_pmg", "label": "BlacklistMaster — PMG Relay", "value_type": "ip", "group": "blacklistmaster"},
            {"type": "suspicious_asn", "label": "ASN Sospechoso", "value_type": "asn", "group": "reference"},
            {"type": "suspicious_token", "label": "Token Exploit / Path", "value_type": "token", "group": "reference"},
        ]
    }


@router.get("")
def list_entries(
    tenant_id: Optional[str] = Query(None, description="Filtrar por tenant (o 'global')"),
    list_type: Optional[str] = Query(None, description="Filtrar por tipo de lista"),
    list_name: Optional[str] = Query(None, description="Filtrar por nombre de lista"),
    rule_code: Optional[str] = Query(None, description="Filtrar por código de regla"),
    enabled: Optional[bool] = Query(None, description="Filtrar por estado activo"),
    search: Optional[str] = Query(None, description="Búsqueda por texto en valor o motivo"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.read")),
) -> Dict[str, Any]:
    """Obtiene catálogo de entradas de listas de seguridad con filtros y paginación."""
    query = db.query(SecurityListEntry)

    # Aislamiento por tenant (salvo admin)
    if ctx.tenant_id != "admin" and not tenant_id:
        query = query.filter(SecurityListEntry.tenant_id.in_([ctx.tenant_id, "global"]))
    elif tenant_id:
        query = query.filter(SecurityListEntry.tenant_id == tenant_id)

    if list_type:
        query = query.filter(SecurityListEntry.list_type == list_type)
    if list_name:
        query = query.filter(SecurityListEntry.list_name == list_name)
    if rule_code:
        query = query.filter(SecurityListEntry.rule_code == rule_code)
    if enabled is not None:
        query = query.filter(SecurityListEntry.enabled == enabled)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            SecurityListEntry.value.ilike(s) | SecurityListEntry.reason.ilike(s)
        )

    total = query.count()
    entries = query.order_by(SecurityListEntry.id.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [e.to_dict() for e in entries],
    }


@router.post("")
def create_entry(
    payload: CreateListEntrySchema,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.write")),
) -> Dict[str, Any]:
    """Crea una nueva entrada en las listas de seguridad con registro de auditoría."""
    exp_dt: Optional[datetime] = None
    if payload.expires_at:
        try:
            exp_dt = datetime.fromisoformat(payload.expires_at.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail="Formato de fecha de expiración inválido. Use ISO 8601.")

    client_ip = request.client.host if request.client else "unknown"
    target_tenant = payload.tenant_id if ctx.tenant_id == "admin" else ctx.tenant_id

    svc = SecurityListService.get_instance()
    entry = svc.create_entry(
        db,
        tenant_id=target_tenant,
        list_type=payload.list_type,
        value=payload.value,
        value_type=payload.value_type,
        list_name=payload.list_name,
        rule_code=payload.rule_code,
        reason=payload.reason,
        expires_at=exp_dt,
        enabled=payload.enabled,
        created_by=ctx.username or ctx.user_id or "admin",
        ip_address=client_ip,
    )

    return {"ok": True, "entry": entry.to_dict()}


@router.get("/audit")
def get_audit_logs(
    entry_id: Optional[int] = Query(None, description="Filtrar auditoría por entrada ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.read")),
) -> Dict[str, Any]:
    """Obtiene registro histórico de auditoría de cambios en listas."""
    query = db.query(SecurityListAudit)
    if entry_id:
        query = query.filter(SecurityListAudit.entry_id == entry_id)

    total = query.count()
    logs = query.order_by(SecurityListAudit.performed_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [l.to_dict() for l in logs],
    }


@router.get("/ignore-log")
def get_ignore_logs(
    tenant_id: Optional[str] = Query(None),
    rule_code: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.read")),
) -> Dict[str, Any]:
    """Obtiene trazabilidad forense de eventos ignorados por reglas de confianza / whitelist."""
    query = db.query(SecurityListIgnoreLog)

    if ctx.tenant_id != "admin" and not tenant_id:
        query = query.filter(SecurityListIgnoreLog.tenant_id.in_([ctx.tenant_id, "global"]))
    elif tenant_id:
        query = query.filter(SecurityListIgnoreLog.tenant_id == tenant_id)

    if rule_code:
        query = query.filter(SecurityListIgnoreLog.rule_code == rule_code)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            SecurityListIgnoreLog.value_matched.ilike(s)
            | SecurityListIgnoreLog.ip_client.ilike(s)
            | SecurityListIgnoreLog.server.ilike(s)
        )

    total = query.count()
    logs = query.order_by(SecurityListIgnoreLog.logged_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [l.to_dict() for l in logs],
    }


@router.post("/cache/refresh")
def refresh_cache(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.write")),
) -> Dict[str, Any]:
    """Fuerza la recarga síncrona del caché de listas de seguridad en memoria."""
    SecurityListService.get_instance().refresh_cache(db)
    return {"ok": True, "message": "Caché de listas de seguridad recargado exitosamente."}


@router.get("/export-json")
def export_json(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.read")),
) -> Dict[str, Any]:
    """Exporta la configuración activa de listas en formato JSON."""
    entries = db.query(SecurityListEntry).filter(SecurityListEntry.enabled.is_(True)).all()
    out = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(entries),
        "entries": [e.to_dict() for e in entries],
    }
    return out


@router.post("/import-json")
def import_json(
    payload: Dict[str, Any],
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.write")),
) -> Dict[str, Any]:
    """Importación masiva de entradas desde payload JSON."""
    raw_entries = payload.get("entries", [])
    if not isinstance(raw_entries, list):
        raise HTTPException(status_code=400, detail="El payload debe contener un array 'entries'.")

    svc = SecurityListService.get_instance()
    client_ip = request.client.host if request.client else "unknown"
    imported = 0

    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        try:
            exp_dt = None
            if item.get("expires_at"):
                exp_dt = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))

            svc.create_entry(
                db,
                tenant_id=str(item.get("tenant_id", ctx.tenant_id)),
                list_type=str(item.get("list_type", "whitelist_ip")),
                value=str(item.get("value", "")),
                value_type=str(item.get("value_type", "ip")),
                list_name=item.get("list_name"),
                rule_code=item.get("rule_code"),
                reason=item.get("reason", "Importado desde JSON"),
                expires_at=exp_dt,
                enabled=bool(item.get("enabled", True)),
                created_by=ctx.username or ctx.user_id or "admin",
                ip_address=client_ip,
            )
            imported += 1
        except Exception as e:
            logger.warning(f"Error al importar ítem {item}: {e}")

    return {"ok": True, "imported": imported}


@router.get("/{entry_id}")
def get_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.read")),
) -> Dict[str, Any]:
    """Obtiene el detalle de una entrada específica por ID."""
    entry = db.query(SecurityListEntry).filter(SecurityListEntry.id == entry_id).one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entrada no encontrada.")
    return {"entry": entry.to_dict()}


@router.put("/{entry_id}")
def update_entry(
    entry_id: int,
    payload: UpdateListEntrySchema,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.write")),
) -> Dict[str, Any]:
    """Actualiza una entrada existente registrando auditoría."""
    client_ip = request.client.host if request.client else "unknown"
    svc = SecurityListService.get_instance()

    update_data = payload.dict(exclude_unset=True)
    if "expires_at" in update_data and update_data["expires_at"]:
        try:
            update_data["expires_at"] = datetime.fromisoformat(update_data["expires_at"].replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail="Formato de fecha de expiración inválido.")

    try:
        entry = svc.update_entry(
            db,
            entry_id=entry_id,
            data=update_data,
            updated_by=ctx.username or ctx.user_id or "admin",
            ip_address=client_ip,
            reason=payload.reason,
        )
        return {"ok": True, "entry": entry.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/{entry_id}")
def delete_entry(
    entry_id: int,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.write")),
) -> Dict[str, Any]:
    """Elimina una entrada de listas de seguridad registrando auditoría."""
    client_ip = request.client.host if request.client else "unknown"
    svc = SecurityListService.get_instance()

    deleted = svc.delete_entry(
        db,
        entry_id=entry_id,
        performed_by=ctx.username or ctx.user_id or "admin",
        ip_address=client_ip,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Entrada no encontrada.")
    return {"ok": True, "message": "Entrada eliminada exitosamente."}


@router.patch("/{entry_id}/toggle")
def toggle_entry(
    entry_id: int,
    payload: ToggleSchema,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("system.write")),
) -> Dict[str, Any]:
    """Activa o desactiva una entrada de listas de seguridad."""
    client_ip = request.client.host if request.client else "unknown"
    svc = SecurityListService.get_instance()

    try:
        entry = svc.toggle_entry(
            db,
            entry_id=entry_id,
            enabled=payload.enabled,
            performed_by=ctx.username or ctx.user_id or "admin",
            ip_address=client_ip,
        )
        return {"ok": True, "entry": entry.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
