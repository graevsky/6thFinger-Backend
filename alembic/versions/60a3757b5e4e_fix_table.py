"""fix table

Revision ID: 60a3757b5e4e
Revises: 251da7966ef9
Create Date: 2026-03-12 18:59:58.507913

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '60a3757b5e4e'
down_revision: Union[str, Sequence[str], None] = '251da7966ef9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
