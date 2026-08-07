"""stage_three_node_contract

Revision ID: d6f4a9b2c8e1
Revises: ab07c302a4a1
Create Date: 2026-08-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d6f4a9b2c8e1"
down_revision: str | Sequence[str] | None = "ab07c302a4a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "nodes",
        "name",
        existing_type=sa.String(length=100),
        type_=sa.String(length=64),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "nodes",
        "name",
        existing_type=sa.String(length=64),
        type_=sa.String(length=100),
        existing_nullable=False,
    )
