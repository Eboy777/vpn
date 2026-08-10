"""managed control ingress discovery

Revision ID: d5f7a9b3e206
Revises: c4e6f8a2d105
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5f7a9b3e206"
down_revision: str | Sequence[str] | None = "c4e6f8a2d105"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "control_ingresses",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("url", sa.String(length=255), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "url ~ '^https://[^/]+$'",
            name=op.f("ck_control_ingresses_https_origin_format"),
        ),
        sa.CheckConstraint(
            "priority BETWEEN 1 AND 1000",
            name=op.f("ck_control_ingresses_priority_range"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_control_ingresses")),
        sa.UniqueConstraint("url", name=op.f("uq_control_ingresses_url")),
    )
    op.create_index(
        "ix_control_ingresses_enabled_priority",
        "control_ingresses",
        ["enabled", "priority", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_control_ingresses_enabled_priority", table_name="control_ingresses")
    op.drop_table("control_ingresses")
