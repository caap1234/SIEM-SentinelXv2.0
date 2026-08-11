"""cleanup_legacy_rawlogs_and_events_tables

Revision ID: f70000000001
Revises: e60000000001
Create Date: 2026-08-11 03:54:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f70000000001'
down_revision = 'f924080e3a94'
branch_labels = None
depends_on = None


def upgrade():
    """
    Elimina limpiamente las tablas de eventos crudos particionados (rawlogs y events) del prototipo monolítico.
    En la arquitectura desacoplada SIEM 2.0:
    - OpenSearch almacena eventos canónicos estructurados (Threat Hunting).
    - MinIO S3 almacena evidencia cruda comprimida (Forensics).
    - PostgreSQL almacena únicamente metadatos SOC (alerts, incidents_v2, entities, tenants, users).
    """
    # 1. Eliminar tabla padre e hijas de rawlogs
    op.execute("DROP TABLE IF EXISTS public.rawlogs CASCADE;")
    op.execute("DROP TABLE IF EXISTS public.rawlogs_old CASCADE;")

    # 2. Eliminar tabla padre e hijas de events legacy
    op.execute("DROP TABLE IF EXISTS public.events CASCADE;")
    op.execute("DROP TABLE IF EXISTS public.events_old CASCADE;")


def downgrade():
    """
    Downgrade sin operación ya que las estructuras relacionales masivas han sido permanentemente
    sustituidas por OpenSearch y MinIO S3.
    """
    pass
