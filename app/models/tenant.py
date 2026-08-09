# app/models/tenant.py
from __future__ import annotations

from sqlalchemy import Column, String, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True, default="default", comment="Identificador único del tenant")
    name = Column(String(255), nullable=False, default="Default Tenant")
    status = Column(String(32), nullable=False, server_default="active", index=True)
    settings = Column(JSONB, nullable=False, server_default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<Tenant id={self.id} name={self.name} status={self.status}>"
