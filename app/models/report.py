from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class Report(Base):
    """
    Tabla de metadatos de reportes en PostgreSQL.
    NO almacena el payload binario/HTML completo de logs ni archivos generados.
    El archivo PDF/HTML final se almacena en MinIO S3 (referenciado por storage_path).
    """
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)

    tenant_id = Column(String(64), nullable=False, server_default="default", index=True)
    type = Column(String(64), nullable=False, index=True)  # executive_weekly, executive_monthly, executive_quarterly, soc_operational, trends, incident_report
    created_by = Column(String(255), nullable=False)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    period_start = Column(DateTime(timezone=True), nullable=True)
    period_end = Column(DateTime(timezone=True), nullable=True)

    format = Column(String(16), nullable=False, server_default="pdf")  # pdf, html, json, csv
    storage_path = Column(Text, nullable=True)  # Objeto MinIO S3 (ej: reports/default/2026/08/rep_101.pdf)
    status = Column(String(32), nullable=False, server_default="completed")  # completed, generating, error

    meta = Column(JSONB, nullable=False, server_default="{}")  # Filtros aplicados y resumen ejecutivo
