# app/models/security_list.py
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityListEntry(Base):
    """
    Entrada individual en el catálogo centralizado de listas de seguridad.
    Soporta Whitelists, Blacklists, Excepciones por regla, Listas de referencia y BlacklistMaster.
    """

    __tablename__ = "security_list_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False, default="global", index=True)

    # Tipo de lista:
    # 'whitelist_ip' | 'whitelist_cidr' | 'trusted_country' | 'trusted_asn' | 'trusted_server'
    # 'exception_rule' | 'list_ref' | 'blm_ignore' | 'blm_shared' | 'blm_pmg'
    # 'suspicious_asn' | 'suspicious_token'
    list_type = Column(String(50), nullable=False, index=True)

    # Valor almacenado (IP, CIDR, ASN, país, token, servidor, etc.)
    value = Column(String(500), nullable=False, index=True)

    # Tipo de dato del valor: 'ip' | 'cidr' | 'asn' | 'country_code' | 'token' | 'username' | 'server'
    value_type = Column(String(30), nullable=False, default="ip")

    # Nombre de lista para list_type='list_ref' (ej: 'privileged_users', 'phishing_path_keywords')
    list_name = Column(String(100), nullable=True, index=True)

    # Código de regla para excepciones específicas (ej: 'AUTH-006')
    rule_code = Column(String(50), nullable=True, index=True)

    # Motivo de la regla/excepción
    reason = Column(Text, nullable=True)

    # Estado activo / inactivo
    enabled = Column(Boolean, nullable=False, default=True, index=True)

    # Fecha de expiración (opcional, NULL = nunca expira)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)

    # Campos de auditoría
    created_by = Column(String(200), nullable=False, default="system")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_by = Column(String(200), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=_utc_now)

    # Relación con auditorías
    audit_logs = relationship(
        "SecurityListAudit",
        back_populates="entry",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> Dict[str, Any]:
        now = _utc_now()
        is_expired = bool(self.expires_at and self.expires_at < now)
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "list_type": self.list_type,
            "value": self.value,
            "value_type": self.value_type,
            "list_name": self.list_name,
            "rule_code": self.rule_code,
            "reason": self.reason,
            "enabled": self.enabled,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": is_expired,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SecurityListAudit(Base):
    """
    Registro histórico de cambios (auditoría) en entradas de listas de seguridad.
    """

    __tablename__ = "security_list_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_id = Column(
        Integer,
        ForeignKey("security_list_entries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Acción realizada: 'create' | 'update' | 'delete' | 'enable' | 'disable'
    action = Column(String(20), nullable=False)

    field_changed = Column(String(100), nullable=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)

    performed_by = Column(String(200), nullable=False, default="system")
    performed_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    ip_address = Column(String(50), nullable=True)
    reason = Column(Text, nullable=True)

    entry = relationship("SecurityListEntry", back_populates="audit_logs")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entry_id": self.entry_id,
            "action": self.action,
            "field_changed": self.field_changed,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "performed_by": self.performed_by,
            "performed_at": self.performed_at.isoformat() if self.performed_at else None,
            "ip_address": self.ip_address,
            "reason": self.reason,
        }


class SecurityListIgnoreLog(Base):
    """
    Trazabilidad forense de eventos descartados / ignorados por reglas de confianza o whitelist.
    Permite responder la pregunta: "¿Por qué no se generó alerta para este evento?"
    """

    __tablename__ = "security_list_ignore_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False, default="global", index=True)

    # Motivo: 'trusted_ip' | 'trusted_country' | 'trusted_asn' | 'trusted_server' | 'rule_exception' | 'blm_ignore' | 'non_global_ip'
    ignore_reason = Column(String(100), nullable=False)

    # Valor que hizo coincidencia
    value_matched = Column(String(500), nullable=False)

    # Regla afectada (si aplica)
    rule_code = Column(String(50), nullable=True, index=True)

    # Referencia al evento original en DB o UUID
    event_id = Column(String(100), nullable=True)
    source = Column(String(100), nullable=True)
    server = Column(String(200), nullable=True)
    ip_client = Column(String(50), nullable=True, index=True)

    logged_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "ignore_reason": self.ignore_reason,
            "value_matched": self.value_matched,
            "rule_code": self.rule_code,
            "event_id": self.event_id,
            "source": self.source,
            "server": self.server,
            "ip_client": self.ip_client,
            "logged_at": self.logged_at.isoformat() if self.logged_at else None,
        }
