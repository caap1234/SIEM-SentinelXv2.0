"""create_rule_list_bindings_table

Revision ID: f80000000001
Revises: f70000000001
Create Date: 2026-08-18 16:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f80000000001'
down_revision = 'f70000000001'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Agregar columnas a rules_v2
    op.add_column(
        'rules_v2',
        sa.Column('detection_bindings_operator', sa.String(length=8), server_default='AND', nullable=False)
    )
    op.add_column(
        'rules_v2',
        sa.Column('legacy_list_policy', sa.Boolean(), server_default='false', nullable=False)
    )

    # 2. Crear tabla rule_list_bindings
    op.create_table(
        'rule_list_bindings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_id', sa.Integer(), sa.ForeignKey('rules_v2.id', ondelete='CASCADE'), nullable=False),
        sa.Column('list_name', sa.String(length=128), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('match_field', sa.String(length=128), nullable=False),
        sa.Column('operator', sa.String(length=32), nullable=False),
        sa.Column('action_config', sa.JSON(), nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_rlb_rule_id', 'rule_list_bindings', ['rule_id'], unique=False)
    op.create_index('ix_rlb_role', 'rule_list_bindings', ['role'], unique=False)
    op.create_index('ix_rlb_list_name', 'rule_list_bindings', ['list_name'], unique=False)


def downgrade():
    op.drop_index('ix_rlb_list_name', table_name='rule_list_bindings')
    op.drop_index('ix_rlb_role', table_name='rule_list_bindings')
    op.drop_index('ix_rlb_rule_id', table_name='rule_list_bindings')
    op.drop_table('rule_list_bindings')
    op.drop_column('rules_v2', 'detection_bindings_operator')
