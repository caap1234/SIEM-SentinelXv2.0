"""merge_heads

Revision ID: fbd8170719ba
Revises: 7015555057f7, e50000000001
Create Date: 2026-08-10 09:47:56.220083

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fbd8170719ba'
down_revision: Union[str, Sequence[str], None] = ('7015555057f7', 'e50000000001')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
