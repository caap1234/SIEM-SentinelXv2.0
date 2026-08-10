"""merge_all_heads

Revision ID: f924080e3a94
Revises: 37734e777cf1, e60000000001
Create Date: 2026-08-10 17:23:39.280024

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f924080e3a94'
down_revision: Union[str, Sequence[str], None] = ('37734e777cf1', 'e60000000001')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
