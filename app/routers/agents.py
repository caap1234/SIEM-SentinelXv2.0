# app/routers/agents.py
"""
API Router para Gestión y Telemetría de Agentes Linux en SentinelX SIEM.
Aplica aislamiento estricto por tenant_id mediante AuthContext.
No incluye acciones defensivas ni ejecución remota de comandos.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.agent import RegisteredAgent
from app.models.tenant import Tenant
from app.schemas.dependencies import AuthContext, require_permission

logger = logging.getLogger("sentinelx.agents")

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


def compute_agent_status(last_seen_at: Optional[datetime]) -> str:
    """
    Calcula el estado del agente según la frescura del último heartbeat:
    - healthy: < 5 minutos
    - delayed: < 30 minutos
    - offline: >= 30 minutos o sin registro
    """
    if not last_seen_at:
        return "offline"
    
    now = datetime.now(timezone.utc)
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)

    diff_seconds = (now - last_seen_at).total_seconds()
    if diff_seconds < 300:  # < 5m
        return "healthy"
    elif diff_seconds < 1800:  # < 30m
        return "delayed"
    else:
        return "offline"


class AgentHeartbeatIn(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = None
    os_info: Optional[str] = None
    kernel: Optional[str] = None
    agent_version: str = "1.0.0"
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


@router.get("")
def list_agents(
    status_filter: Optional[str] = Query(None, description="Filtrar por estado: healthy|delayed|offline"),
    hostname: Optional[str] = Query(None, description="Filtrar por nombre de host"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("agents.manage")),
) -> Dict[str, Any]:
    """
    Lista los agentes registrados para el tenant_id autenticado con su estado de salud en tiempo real.
    """
    query = db.query(RegisteredAgent).filter(RegisteredAgent.tenant_id == ctx.tenant_id)

    if hostname:
        query = query.filter(RegisteredAgent.hostname.ilike(f"%{hostname}%"))

    total = query.count()
    agents_db = query.order_by(RegisteredAgent.last_seen_at.desc().nullslast()).offset(offset).limit(limit).all()

    agents_list = []
    healthy_count = 0
    delayed_count = 0
    offline_count = 0

    for ag in agents_db:
        computed_st = compute_agent_status(ag.last_seen_at)
        if computed_st == "healthy":
            healthy_count += 1
        elif computed_st == "delayed":
            delayed_count += 1
        else:
            offline_count += 1

        if status_filter and computed_st != status_filter.lower():
            continue

        agents_list.append({
            "id": str(ag.id),
            "tenant_id": ag.tenant_id,
            "name": ag.name or ag.hostname,
            "hostname": ag.hostname,
            "ip_address": ag.ip_address or "—",
            "os_info": ag.os_info or "Linux genérico",
            "agent_version": ag.agent_version,
            "status": computed_st,
            "metadata_json": ag.metadata_json or {},
            "last_seen_at": ag.last_seen_at.isoformat() if ag.last_seen_at else None,
            "created_at": ag.created_at.isoformat() if ag.created_at else None,
        })

    return {
        "tenant_id": ctx.tenant_id,
        "total": total,
        "summary": {
            "healthy": healthy_count,
            "delayed": delayed_count,
            "offline": offline_count,
            "total": total,
        },
        "agents": agents_list,
    }


@router.get("/{agent_id}")
def get_agent_detail(
    agent_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("agents.manage")),
) -> Dict[str, Any]:
    """
    Obtiene el detalle completo de telemetría de un agente registrado.
    """
    try:
        ag_uuid = UUID(agent_id)
        ag = db.query(RegisteredAgent).filter(
            RegisteredAgent.id == ag_uuid,
            RegisteredAgent.tenant_id == ctx.tenant_id,
        ).first()
    except Exception:
        ag = None

    if not ag:
        # Búsqueda por hostname como fallback
        ag = db.query(RegisteredAgent).filter(
            RegisteredAgent.hostname == agent_id,
            RegisteredAgent.tenant_id == ctx.tenant_id,
        ).first()

    if not ag:
        raise HTTPException(status_code=404, detail=f"Agente '{agent_id}' no encontrado en tenant '{ctx.tenant_id}'")

    computed_st = compute_agent_status(ag.last_seen_at)

    return {
        "id": str(ag.id),
        "tenant_id": ag.tenant_id,
        "name": ag.name or ag.hostname,
        "hostname": ag.hostname,
        "ip_address": ag.ip_address or "—",
        "os_info": ag.os_info or "Linux",
        "agent_version": ag.agent_version,
        "status": computed_st,
        "metadata_json": ag.metadata_json or {},
        "last_seen_at": ag.last_seen_at.isoformat() if ag.last_seen_at else None,
        "created_at": ag.created_at.isoformat() if ag.created_at else None,
        "recent_telemetry_events": [
            {
                "event_type": "heartbeat",
                "timestamp": ag.last_seen_at.isoformat() if ag.last_seen_at else None,
                "status": computed_st,
                "detail": f"Telemetry check-in from {ag.hostname} ({ag.ip_address})",
            }
        ],
    }


@router.post("/heartbeat")
def record_agent_heartbeat(
    payload: AgentHeartbeatIn,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_permission("ingest.read")),
) -> Dict[str, Any]:
    """
    Registra o actualiza la telemetría heartbeat enviada por el SentinelX Agent.
    """
    now = datetime.now(timezone.utc)

    ag = db.query(RegisteredAgent).filter(
        RegisteredAgent.hostname == payload.hostname,
        RegisteredAgent.tenant_id == ctx.tenant_id,
    ).first()

    if not ag:
        ag = RegisteredAgent(
            tenant_id=ctx.tenant_id,
            name=payload.hostname,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            os_info=payload.os_info,
            agent_version=payload.agent_version,
            status="healthy",
            metadata_json={"kernel": payload.kernel, **payload.metadata_json},
            last_seen_at=now,
        )
        db.add(ag)
    else:
        ag.ip_address = payload.ip_address or ag.ip_address
        ag.os_info = payload.os_info or ag.os_info
        ag.agent_version = payload.agent_version or ag.agent_version
        ag.status = "healthy"
        ag.last_seen_at = now
        meta = ag.metadata_json or {}
        if payload.kernel:
            meta["kernel"] = payload.kernel
        meta.update(payload.metadata_json)
        ag.metadata_json = meta

    db.commit()
    db.refresh(ag)

    return {
        "ok": True,
        "agent_id": str(ag.id),
        "status": "healthy",
        "last_seen_at": ag.last_seen_at.isoformat() if ag.last_seen_at else None,
    }
