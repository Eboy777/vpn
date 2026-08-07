"""stage_four_snapshot_issues

Revision ID: e4a1c7d9f203
Revises: d6f4a9b2c8e1
Create Date: 2026-08-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e4a1c7d9f203"
down_revision: str | Sequence[str] | None = "d6f4a9b2c8e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_nodes_status_values"), "nodes", type_="check")
    op.create_check_constraint(
        op.f("ck_nodes_status_values"),
        "nodes",
        "status IN ('warming','active','quiescing','draining','dead','blocked')",
    )
    op.create_table(
        "node_snapshot_issues",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("node_id", sa.UUID(), nullable=False),
        sa.Column("revision", sa.String(length=64), nullable=False),
        sa.Column("snapshot_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "revision ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_node_snapshot_issues_revision_format"),
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_node_snapshot_issues_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_node_snapshot_issues")),
        sa.UniqueConstraint(
            "node_id",
            "revision",
            name="uq_node_snapshot_issue_revision",
        ),
    )
    op.create_index(
        "ix_node_snapshot_issues_expiry",
        "node_snapshot_issues",
        ["snapshot_valid_until"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_node_snapshot_issues_expiry", table_name="node_snapshot_issues")
    op.drop_table("node_snapshot_issues")
    op.drop_constraint(op.f("ck_nodes_status_values"), "nodes", type_="check")
    op.create_check_constraint(
        op.f("ck_nodes_status_values"),
        "nodes",
        "status IN ('active','draining','dead','blocked')",
    )
