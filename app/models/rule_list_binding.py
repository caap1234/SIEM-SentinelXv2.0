from __future__ import annotations

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db import Base


class RuleListBinding(Base):
    __tablename__ = "rule_list_bindings"

    id = Column(Integer, primary_key=True, autoincrement=True)

    rule_id = Column(Integer, ForeignKey("rules_v2.id", ondelete="CASCADE"), nullable=False)
    
    # Nombre exacto de la lista (ej. whitelist_ip, suspicious_asn_numbers)
    list_name = Column(String(128), nullable=False)
    
    # Rol de la lista en la regla: exclusion, detection, context
    role = Column(String(32), nullable=False)
    
    # Campo ECS a evaluar (ej. source.ip, url.path, client.ip)
    match_field = Column(String(128), nullable=False)
    
    # Operador de comparación (ej. in_ref, not_in_ref, contains_any_ref, cidr_match)
    operator = Column(String(64), nullable=False)
    
    # Configuración dinámica opcional para roles como context (ej. adjust_severity, set_metadata)
    action_config = Column(JSONB, nullable=False, server_default="{}")
    
    enabled = Column(Boolean, nullable=False, server_default="true")

    rule = relationship("RuleV2", back_populates="bindings")
