"""add_alerts_opensearch_event_id_and_s3_key

Revision ID: 4e1ea9c89d5f
Revises: fbd8170719ba
Create Date: 2026-08-10 09:48:14.911328

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4e1ea9c89d5f'
down_revision: Union[str, Sequence[str], None] = 'fbd8170719ba'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add opensearch_event_id and s3_key columns + indexes to alerts table."""
    op.add_column('alerts', sa.Column('opensearch_event_id', sa.String(length=255), nullable=True))
    op.add_column('alerts', sa.Column('s3_key', sa.String(length=512), nullable=True))
    op.create_index(op.f('ix_alerts_opensearch_event_id'), 'alerts', ['opensearch_event_id'], unique=False)
    op.create_index(op.f('ix_alerts_s3_key'), 'alerts', ['s3_key'], unique=False)


def downgrade() -> None:
    """Downgrade schema: drop opensearch_event_id and s3_key columns + indexes from alerts table."""
    op.drop_index(op.f('ix_alerts_s3_key'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_opensearch_event_id'), table_name='alerts')
    op.drop_column('alerts', 's3_key')
    op.drop_column('alerts', 'opensearch_event_id')
