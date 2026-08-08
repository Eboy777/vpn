"""node_snapshot_watchdog

Revision ID: f7b2d4a6c801
Revises: e4a1c7d9f203
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7b2d4a6c801"
down_revision: str | Sequence[str] | None = "e4a1c7d9f203"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "nodes",
        sa.Column("applied_snapshot_valid_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "nodes",
        sa.Column("credentials_source_fingerprint", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "nodes",
        sa.Column("snapshot_ack_deadline", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "nodes",
        sa.Column(
            "snapshot_ack_failures",
            sa.SmallInteger(),
            server_default="0",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        op.f("ck_nodes_credentials_source_fingerprint_format"),
        "nodes",
        "credentials_source_fingerprint IS NULL "
        "OR credentials_source_fingerprint ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        op.f("ck_nodes_snapshot_ack_failures_nonnegative"),
        "nodes",
        "snapshot_ack_failures >= 0",
    )
    op.create_index(
        "ix_nodes_snapshot_watchdog",
        "nodes",
        ["status", "snapshot_ack_deadline"],
        unique=False,
    )
    op.execute(
        """
        UPDATE nodes
        SET applied_snapshot_valid_until = snapshot_valid_until
        WHERE applied_credentials_revision = credentials_revision
          AND applied_credentials_revision IS NOT NULL
        """
    )


def downgrade() -> None:
    op.drop_index("ix_nodes_snapshot_watchdog", table_name="nodes")
    op.drop_constraint(
        op.f("ck_nodes_snapshot_ack_failures_nonnegative"),
        "nodes",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_nodes_credentials_source_fingerprint_format"),
        "nodes",
        type_="check",
    )
    op.drop_column("nodes", "snapshot_ack_failures")
    op.drop_column("nodes", "snapshot_ack_deadline")
    op.drop_column("nodes", "applied_snapshot_valid_until")
    op.drop_column("nodes", "credentials_source_fingerprint")
