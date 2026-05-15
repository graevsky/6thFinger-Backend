"""Fix device settings version type

Revision ID: d91b3b4c8f6a
Revises: 7644fd5cfa6f
Create Date: 2026-05-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d91b3b4c8f6a"
down_revision: Union[str, Sequence[str], None] = "7644fd5cfa6f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        ALTER TABLE device_settings
        ALTER COLUMN version TYPE INTEGER
        USING COALESCE(
            NULLIF(regexp_replace(version, '[^0-9]', '', 'g'), ''),
            '0'
        )::integer
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column(
        "device_settings",
        "version",
        existing_type=sa.Integer(),
        type_=sa.String(length=32),
        postgresql_using="version::text",
    )
