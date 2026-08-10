"""operations analytics and node telemetry

Revision ID: a8c4e2f1b903
Revises: f7b2d4a6c801
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a8c4e2f1b903"
down_revision: str | Sequence[str] | None = "f7b2d4a6c801"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("last_ip", sa.String(length=45), nullable=True))
    op.add_column("devices", sa.Column("last_ip_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "extension_installations",
        sa.Column("installation_id", sa.UUID(), nullable=False),
        sa.Column("extension_version", sa.String(length=32), nullable=False),
        sa.Column("launch_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "launch_count >= 0", name=op.f("ck_extension_installations_launch_count_nonnegative")
        ),
        sa.PrimaryKeyConstraint("installation_id", name=op.f("pk_extension_installations")),
    )
    op.create_index(
        "ix_extension_installations_last_seen", "extension_installations", ["last_seen_at"]
    )
    op.create_table(
        "extension_lifecycle_events",
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("installation_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=16), nullable=False),
        sa.Column("extension_version", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "event_type IN ('installed','launched','updated')",
            name=op.f("ck_extension_lifecycle_events_event_type_values"),
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_extension_lifecycle_events")),
    )
    op.create_index(
        "ix_extension_lifecycle_installation",
        "extension_lifecycle_events",
        ["installation_id", "received_at"],
    )

    op.create_table(
        "vpn_sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("node_id", sa.UUID(), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("extension_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("connection_errors", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active','ended','error')", name=op.f("ck_vpn_sessions_status_values")
        ),
        sa.CheckConstraint(
            "connection_errors >= 0", name=op.f("ck_vpn_sessions_connection_errors_nonnegative")
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_vpn_sessions_device_id_devices"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_vpn_sessions_node_id_nodes"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_vpn_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vpn_sessions")),
    )
    op.create_index("ix_vpn_sessions_user_started", "vpn_sessions", ["user_id", "started_at"])
    op.create_index("ix_vpn_sessions_active", "vpn_sessions", ["status", "last_seen_at"])
    op.create_table(
        "user_activity_events",
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("node_id", sa.UUID(), nullable=True),
        sa.Column("session_id", sa.UUID(), nullable=True),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "event_type IN ("
            "'vpn_started','vpn_heartbeat','vpn_stopped','connection_error',"
            "'node_selected','payment_link_created'"
            ")",
            name=op.f("ck_user_activity_events_event_type_values"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_user_activity_events_device_id_devices"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_user_activity_events_node_id_nodes"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_activity_events_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_user_activity_events")),
    )
    op.create_index(
        "ix_user_activity_user_received", "user_activity_events", ["user_id", "received_at"]
    )

    op.create_table(
        "node_telemetry_reports",
        sa.Column("report_id", sa.UUID(), nullable=False),
        sa.Column("node_id", sa.UUID(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "request_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_node_telemetry_reports_request_hash_format"),
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_node_telemetry_reports_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("report_id", name=op.f("pk_node_telemetry_reports")),
    )
    op.create_index(
        "ix_node_telemetry_node_received", "node_telemetry_reports", ["node_id", "received_at"]
    )
    op.create_table(
        "node_user_traffic",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("node_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("total_connections", sa.BigInteger(), nullable=False),
        sa.Column("current_connections", sa.BigInteger(), nullable=False),
        sa.Column("input_bytes", sa.BigInteger(), nullable=False),
        sa.Column("output_bytes", sa.BigInteger(), nullable=False),
        sa.Column("total_errors", sa.BigInteger(), nullable=False),
        sa.Column("connection_seconds", sa.BigInteger(), nullable=False),
        sa.Column("last_reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "connection_seconds >= 0",
            name=op.f("ck_node_user_traffic_connection_seconds_nonnegative"),
        ),
        sa.CheckConstraint(
            "current_connections >= 0",
            name=op.f("ck_node_user_traffic_current_connections_nonnegative"),
        ),
        sa.CheckConstraint(
            "input_bytes >= 0", name=op.f("ck_node_user_traffic_input_bytes_nonnegative")
        ),
        sa.CheckConstraint(
            "output_bytes >= 0", name=op.f("ck_node_user_traffic_output_bytes_nonnegative")
        ),
        sa.CheckConstraint(
            "total_connections >= 0",
            name=op.f("ck_node_user_traffic_total_connections_nonnegative"),
        ),
        sa.CheckConstraint(
            "total_errors >= 0", name=op.f("ck_node_user_traffic_total_errors_nonnegative")
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_node_user_traffic_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_node_user_traffic_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_node_user_traffic")),
        sa.UniqueConstraint("node_id", "user_id", name="uq_node_user_traffic_node_user"),
    )
    op.create_index("ix_node_user_traffic_user", "node_user_traffic", ["user_id"])
    op.create_table(
        "node_runtime_metrics",
        sa.Column("node_id", sa.UUID(), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("memory_percent", sa.Float(), nullable=False),
        sa.Column("disk_percent", sa.Float(), nullable=False),
        sa.Column("network_rx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("network_tx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("gost_up", sa.Boolean(), nullable=False),
        sa.Column("sync_agent_up", sa.Boolean(), nullable=False),
        sa.Column("tls_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_node_runtime_metrics_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("node_id", name=op.f("pk_node_runtime_metrics")),
    )
    op.create_table(
        "canary_runs",
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("canary_id", sa.UUID(), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "request_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_canary_runs_request_hash_format"),
        ),
        sa.ForeignKeyConstraint(
            ["canary_id"],
            ["canaries.id"],
            name=op.f("fk_canary_runs_canary_id_canaries"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_canary_runs")),
    )


def downgrade() -> None:
    op.drop_table("canary_runs")
    op.drop_table("node_runtime_metrics")
    op.drop_index("ix_node_user_traffic_user", table_name="node_user_traffic")
    op.drop_table("node_user_traffic")
    op.drop_index("ix_node_telemetry_node_received", table_name="node_telemetry_reports")
    op.drop_table("node_telemetry_reports")
    op.drop_index("ix_user_activity_user_received", table_name="user_activity_events")
    op.drop_table("user_activity_events")
    op.drop_index("ix_vpn_sessions_active", table_name="vpn_sessions")
    op.drop_index("ix_vpn_sessions_user_started", table_name="vpn_sessions")
    op.drop_table("vpn_sessions")
    op.drop_index("ix_extension_lifecycle_installation", table_name="extension_lifecycle_events")
    op.drop_table("extension_lifecycle_events")
    op.drop_index("ix_extension_installations_last_seen", table_name="extension_installations")
    op.drop_table("extension_installations")
    op.drop_column("devices", "last_ip_at")
    op.drop_column("devices", "last_ip")
