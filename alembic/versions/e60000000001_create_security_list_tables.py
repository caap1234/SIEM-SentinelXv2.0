"""create_security_list_tables

Revision ID: e60000000001
Revises: e50000000001
Create Date: 2026-08-10 19:42:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e60000000001'
down_revision = 'e50000000001'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Tabla security_list_entries
    op.create_table(
        'security_list_entries',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.String(length=100), server_default='global', nullable=False),
        sa.Column('list_type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=500), nullable=False),
        sa.Column('value_type', sa.String(length=30), server_default='ip', nullable=False),
        sa.Column('list_name', sa.String(length=100), nullable=True),
        sa.Column('rule_code', sa.String(length=50), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(length=200), server_default='system', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_by', sa.String(length=200), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_sle_tenant_id', 'security_list_entries', ['tenant_id'], unique=False)
    op.create_index('ix_sle_list_type', 'security_list_entries', ['list_type'], unique=False)
    op.create_index('ix_sle_value', 'security_list_entries', ['value'], unique=False)
    op.create_index('ix_sle_list_name', 'security_list_entries', ['list_name'], unique=False)
    op.create_index('ix_sle_rule_code', 'security_list_entries', ['rule_code'], unique=False)
    op.create_index('ix_sle_enabled', 'security_list_entries', ['enabled'], unique=False)
    op.create_index('ix_sle_expires_at', 'security_list_entries', ['expires_at'], unique=False)

    # 2. Tabla security_list_audit
    op.create_table(
        'security_list_audit',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('entry_id', sa.Integer(), sa.ForeignKey('security_list_entries.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('field_changed', sa.String(length=100), nullable=True),
        sa.Column('old_value', sa.Text(), nullable=True),
        sa.Column('new_value', sa.Text(), nullable=True),
        sa.Column('performed_by', sa.String(length=200), server_default='system', nullable=False),
        sa.Column('performed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_sla_entry_id', 'security_list_audit', ['entry_id'], unique=False)
    op.create_index('ix_sla_performed_at', 'security_list_audit', ['performed_at'], unique=False)

    # 3. Tabla security_list_ignore_log
    op.create_table(
        'security_list_ignore_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.String(length=100), server_default='global', nullable=False),
        sa.Column('ignore_reason', sa.String(length=100), nullable=False),
        sa.Column('value_matched', sa.String(length=500), nullable=False),
        sa.Column('rule_code', sa.String(length=50), nullable=True),
        sa.Column('event_id', sa.String(length=100), nullable=True),
        sa.Column('source', sa.String(length=100), nullable=True),
        sa.Column('server', sa.String(length=200), nullable=True),
        sa.Column('ip_client', sa.String(length=50), nullable=True),
        sa.Column('logged_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_slil_tenant_id', 'security_list_ignore_log', ['tenant_id'], unique=False)
    op.create_index('ix_slil_rule_code', 'security_list_ignore_log', ['rule_code'], unique=False)
    op.create_index('ix_slil_ip_client', 'security_list_ignore_log', ['ip_client'], unique=False)
    op.create_index('ix_slil_logged_at', 'security_list_ignore_log', ['logged_at'], unique=False)


def downgrade():
    op.drop_table('security_list_ignore_log')
    op.drop_table('security_list_audit')
    op.drop_table('security_list_entries')
