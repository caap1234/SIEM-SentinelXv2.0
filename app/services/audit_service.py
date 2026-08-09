# app/services/audit_service.py
"""
Servicio de Auditoría Administrativa y de Seguridad en PostgreSQL.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger("sentinelx.audit")


def log_audit_event(
    db: Session,
    username: str,
    action: str,
    tenant_id: str = "default",
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
    user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Registra una entrada de auditoría en la base de datos PostgreSQL.
    """
    entry = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        ip_address=ip_address,
        status=status,
        details=details or {},
    )
    try:
        db.add(entry)
        db.commit()
        db.refresh(entry)
        logger.info("Auditoría [%s]: usuario=%s acción=%s recurso=%s status=%s", tenant_id, username, action, resource, status)
        return entry
    except Exception as e:
        db.rollback()
        logger.error("Error al registrar auditoría en PostgreSQL: %s", e)
        raise
