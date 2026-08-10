# app/services/agent_api_key_service.py
"""
Servicio de Gestión y Validación Segura de API Keys de Agente (PostgreSQL).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from app.models.agent_api_key import AgentApiKey


def generate_key_secret() -> str:
    """Genera una clave API aleatoria de alta entropía con prefijo sx_live_."""
    return f"sx_live_{secrets.token_hex(24)}"


def hash_key_secret(raw_key: str) -> str:
    """Genera el hash SHA-256 de la clave API para almacenamiento seguro."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def create_agent_api_key(
    db: Session,
    name: str,
    tenant_id: str = "default",
    agent_id: Optional[str] = None,
    expires_at: Optional[datetime] = None,
) -> Tuple[str, AgentApiKey]:
    """
    Crea una nueva API Key para agente. Retorna la clave cruda (solo visible una vez) y el objeto ORM.
    """
    raw_key = generate_key_secret()
    key_hash = hash_key_secret(raw_key)

    record = AgentApiKey(
        tenant_id=tenant_id,
        agent_id=agent_id,
        name=name,
        key_hash=key_hash,
        status="active",
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return raw_key, record


def validate_agent_api_key(db: Session, raw_key: str) -> Optional[AgentApiKey]:
    """
    Valida una clave API cruda contra PostgreSQL. Retorna la entidad AgentApiKey si es válida y activa.
    """
    if not raw_key or not isinstance(raw_key, str):
        return None

    key_hash = hash_key_secret(raw_key)
    record = db.query(AgentApiKey).filter(AgentApiKey.key_hash == key_hash).first()

    if not record:
        return None

    if record.status != "active":
        return None

    if record.expires_at and record.expires_at < datetime.now(timezone.utc):
        record.status = "expired"
        db.commit()
        return None

    record.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return record


def revoke_agent_api_key(db: Session, key_id: Any) -> bool:
    """Revoca una clave API activa."""
    import uuid as uuid_lib
    if isinstance(key_id, str):
        try:
            key_id = uuid_lib.UUID(key_id)
        except Exception:
            pass
    record = db.query(AgentApiKey).filter(AgentApiKey.id == key_id).first()
    if not record:
        return False
    record.status = "revoked"
    db.commit()
    return True

