"""connection quality and capacity analytics

Revision ID: c4e6f8a2d105
Revises: a8c4e2f1b903
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4e6f8a2d105"
down_revision: str | Sequence[str] | None = "a8c4e2f1b903"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _client_columns(table: str) -> None:
    for name in ("browser_name", "browser_version", "platform"):
        op.add_column(
            table,
            sa.Column(name, sa.String(length=32), server_default="unknown", nullable=False),
        )


def upgrade() -> None:
    _client_columns("extension_installations")
    _client_columns("extension_lifecycle_events")
    _client_columns("vpn_sessions")
    _client_columns("user_activity_events")

    op.add_column("vpn_sessions", sa.Column("connection_duration_ms", sa.Integer()))
    op.add_column(
        "vpn_sessions",
        sa.Column("failover_count", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "vpn_sessions",
        sa.Column("reconnect_count", sa.Integer(), server_default="0", nullable=False),
    )
    op.create_check_constraint(
        op.f("ck_vpn_sessions_connection_duration_nonnegative"),
        "vpn_sessions",
        "connection_duration_ms IS NULL OR connection_duration_ms >= 0",
    )
    op.create_check_constraint(
        op.f("ck_vpn_sessions_failover_count_nonnegative"),
        "vpn_sessions",
        "failover_count >= 0",
    )
    op.create_check_constraint(
        op.f("ck_vpn_sessions_reconnect_count_nonnegative"),
        "vpn_sessions",
        "reconnect_count >= 0",
    )

    op.add_column("user_activity_events", sa.Column("duration_ms", sa.Integer()))
    op.add_column(
        "user_activity_events",
        sa.Column(
            "extension_version",
            sa.String(length=32),
            server_default="unknown",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        op.f("ck_user_activity_events_duration_nonnegative"),
        "user_activity_events",
        "duration_ms IS NULL OR duration_ms >= 0",
    )
    op.drop_constraint(
        op.f("ck_user_activity_events_event_type_values"),
        "user_activity_events",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_user_activity_events_event_type_values"),
        "user_activity_events",
        "event_type IN ("
        "'connection_attempt','vpn_started','vpn_heartbeat','vpn_stopped',"
        "'connection_error','node_selected','node_failover','reconnect',"
        "'tariff_viewed','payment_link_created'"
        ")",
    )
    op.create_index("ix_vpn_sessions_started", "vpn_sessions", ["started_at"])
    op.create_index(
        "ix_user_activity_type_received",
        "user_activity_events",
        ["event_type", "received_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_user_activity_type_received", table_name="user_activity_events")
    op.drop_index("ix_vpn_sessions_started", table_name="vpn_sessions")
    op.drop_constraint(
        op.f("ck_user_activity_events_event_type_values"),
        "user_activity_events",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_user_activity_events_event_type_values"),
        "user_activity_events",
        "event_type IN ("
        "'vpn_started','vpn_heartbeat','vpn_stopped','connection_error',"
        "'node_selected','payment_link_created'"
        ")",
    )
    op.drop_constraint(
        op.f("ck_user_activity_events_duration_nonnegative"),
        "user_activity_events",
        type_="check",
    )
    op.drop_column("user_activity_events", "extension_version")
    op.drop_column("user_activity_events", "duration_ms")

    for name in (
        "reconnect_count_nonnegative",
        "failover_count_nonnegative",
        "connection_duration_nonnegative",
    ):
        op.drop_constraint(op.f(f"ck_vpn_sessions_{name}"), "vpn_sessions", type_="check")
    op.drop_column("vpn_sessions", "reconnect_count")
    op.drop_column("vpn_sessions", "failover_count")
    op.drop_column("vpn_sessions", "connection_duration_ms")

    for table in (
        "user_activity_events",
        "vpn_sessions",
        "extension_lifecycle_events",
        "extension_installations",
    ):
        for name in ("platform", "browser_version", "browser_name"):
            op.drop_column(table, name)
