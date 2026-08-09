# app/models/agent.py
from __future__ import annotations

import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db import Base


class RegisteredAgent(Base):
    __tablename__ = "registered_agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, default="default", index=True)

    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True)
    os_info = Column(String(255), nullable=True)  # e.g., AlmaLinux 9.4, CloudLinux 8.9
    status = Column(String(32), nullable=False, server_default="healthy", index=True)  # healthy | delayed | offline | spool_warning
    agent_version = Column(String(32), nullable=False, default="1.0.0")

    metadata_json = Column(JSONB, nullable=False, server_default="{}")
    last_seen_at = Column(DateTime(timezone=True), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<RegisteredAgent hostname={self.hostname} status={self.status} tenant={self.tenant_id}>"
