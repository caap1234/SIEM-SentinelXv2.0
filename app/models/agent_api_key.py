# app/models/agent_api_key.py
from __future__ import annotations

import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID

from app.db import Base


class AgentApiKey(Base):
    __tablename__ = "agent_api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, default="default", index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("registered_agents.id", ondelete="SET NULL"), nullable=True, index=True)

    name = Column(String(255), nullable=False)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    status = Column(String(32), nullable=False, server_default="active", index=True)  # active | revoked | expired

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<AgentApiKey id={self.id} name={self.name} tenant={self.tenant_id} status={self.status}>"
