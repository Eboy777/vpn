"""stage_two_pairing_rate_limits

Revision ID: ab07c302a4a1
Revises: 0e223e32027d
Create Date: 2026-08-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "ab07c302a4a1"
down_revision: str | Sequence[str] | None = "0e223e32027d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("scope", sa.String(length=64), nullable=False),
        sa.Column("subject_hash", sa.LargeBinary(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "octet_length(subject_hash) = 32",
            name=op.f("ck_rate_limit_counters_subject_hash_length"),
        ),
        sa.CheckConstraint(
            "request_count > 0",
            name=op.f("ck_rate_limit_counters_request_count_positive"),
        ),
        sa.PrimaryKeyConstraint(
            "scope",
            "subject_hash",
            "window_start",
            name=op.f("pk_rate_limit_counters"),
        ),
    )
    op.create_index(
        "ix_rate_limit_counters_window",
        "rate_limit_counters",
        ["window_start"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limit_counters_window", table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
