# app/models/audit_log.py
from __future__ import annotations

import uuid
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, default="default", index=True)

    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(128), nullable=False, index=True)
    action = Column(String(128), nullable=False, index=True)  # e.g., login, create_rule, update_config, soar_block
    resource = Column(String(255), nullable=True)  # e.g., rule:12, ip:198.51.100.1
    ip_address = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="success", index=True)  # success | failure

    details = Column(JSONB, nullable=False, server_default="{}")
    timestamp_utc = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action} username={self.username} status={self.status} tenant={self.tenant_id}>"
