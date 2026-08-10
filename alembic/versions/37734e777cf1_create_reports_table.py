"""create_reports_table

Revision ID: 37734e777cf1
Revises: 4e1ea9c89d5f
Create Date: 2026-08-10 10:41:33.409886

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '37734e777cf1'
down_revision: Union[str, Sequence[str], None] = '4e1ea9c89d5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.String(length=64), server_default='default', nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('format', sa.String(length=16), server_default='pdf', nullable=False),
        sa.Column('storage_path', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), server_default='completed', nullable=False),
        sa.Column('meta', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reports_created_at'), 'reports', ['created_at'], unique=False)
    op.create_index(op.f('ix_reports_tenant_id'), 'reports', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_reports_type'), 'reports', ['type'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_reports_type'), table_name='reports')
    op.drop_index(op.f('ix_reports_tenant_id'), table_name='reports')
    op.drop_index(op.f('ix_reports_created_at'), table_name='reports')
    op.drop_table('reports')
