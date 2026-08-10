from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vpn_service.domain.enums import (
    AuthTokenStatus,
    CanaryStatus,
    DeviceStatus,
    NodeSelectionMode,
    NodeStatus,
    OutboxStatus,
    PaymentStatus,
    UserStatus,
)
from vpn_service.persistence.base import Base


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def created_at_column() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class Node(Base):
    __tablename__ = "nodes"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="port_range"),
        CheckConstraint("capacity_users > 0", name="positive_capacity"),
        CheckConstraint("failed_checks >= 0", name="failed_checks_nonnegative"),
        CheckConstraint("successful_checks >= 0", name="successful_checks_nonnegative"),
        CheckConstraint("country_code ~ '^[A-Z]{2}$'", name="country_code_format"),
        CheckConstraint(
            "status IN ('warming','active','quiescing','draining','dead','blocked')",
            name="status_values",
        ),
        CheckConstraint(
            "credentials_revision IS NULL OR credentials_revision ~ '^[0-9a-f]{64}$'",
            name="credentials_revision_format",
        ),
        CheckConstraint(
            "credentials_source_fingerprint IS NULL "
            "OR credentials_source_fingerprint ~ '^[0-9a-f]{64}$'",
            name="credentials_source_fingerprint_format",
        ),
        CheckConstraint(
            "applied_credentials_revision IS NULL "
            "OR applied_credentials_revision ~ '^[0-9a-f]{64}$'",
            name="applied_revision_format",
        ),
        CheckConstraint("snapshot_ack_failures >= 0", name="snapshot_ack_failures_nonnegative"),
        Index("ix_nodes_assignment", "status", "capacity_users", "id"),
        Index("ix_nodes_snapshot_watchdog", "status", "snapshot_ack_deadline"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    country_code: Mapped[str] = mapped_column(String(2), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=NodeStatus.DEAD.value, server_default="dead"
    )
    capacity_users: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_checks: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    successful_checks: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    recovery_ready: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    credentials_revision: Mapped[str | None] = mapped_column(String(64))
    credentials_source_fingerprint: Mapped[str | None] = mapped_column(String(64))
    applied_credentials_revision: Mapped[str | None] = mapped_column(String(64))
    snapshot_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_snapshot_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    snapshot_ack_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    snapshot_ack_failures: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("status IN ('active','blocked')", name="status_values"),
        CheckConstraint("node_selection_mode IN ('auto','manual')", name="selection_mode_values"),
        CheckConstraint(
            "proxy_username ~ '^u_[a-z0-9]{26}$'",
            name="proxy_username_format",
        ),
        CheckConstraint("octet_length(proxy_password_ciphertext) > 0", name="password_nonempty"),
        Index("uq_users_proxy_username_lower", text("lower(proxy_username)"), unique=True),
        Index("ix_users_assignment_access", "assigned_node_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    telegram_id: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=UserStatus.ACTIVE.value, server_default="active"
    )
    trial_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    subscription_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assigned_node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("nodes.id", ondelete="SET NULL"),
        nullable=True,
    )
    node_selection_mode: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=NodeSelectionMode.AUTO.value,
        server_default="auto",
    )
    proxy_username: Mapped[str] = mapped_column(String(28), nullable=False)
    proxy_password_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    proxy_password_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = created_at_column()


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("status IN ('pending','active','revoked')", name="status_values"),
        CheckConstraint(
            "(status = 'pending') OR user_id IS NOT NULL",
            name="bound_device_has_user",
        ),
        CheckConstraint(
            "device_token_hash IS NULL OR octet_length(device_token_hash) = 32",
            name="device_token_hash_length",
        ),
        CheckConstraint(
            "pairing_session_token_hash IS NULL OR octet_length(pairing_session_token_hash) = 32",
            name="pairing_session_hash_length",
        ),
        CheckConstraint(
            "telegram_start_token_hash IS NULL OR octet_length(telegram_start_token_hash) = 32",
            name="telegram_start_hash_length",
        ),
        Index("ix_devices_pairing_expiry", "status", "pairing_expires_at"),
        Index("ix_devices_user_status", "user_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    device_token_hash: Mapped[bytes | None] = mapped_column(LargeBinary, unique=True)
    device_token_key_id: Mapped[str | None] = mapped_column(String(64))
    pairing_session_token_hash: Mapped[bytes | None] = mapped_column(LargeBinary, unique=True)
    pairing_session_token_key_id: Mapped[str | None] = mapped_column(String(64))
    telegram_start_token_hash: Mapped[bytes | None] = mapped_column(LargeBinary, unique=True)
    telegram_start_token_key_id: Mapped[str | None] = mapped_column(String(64))
    pairing_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pairing_error_code: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DeviceStatus.PENDING.value, server_default="pending"
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ip: Mapped[str | None] = mapped_column(String(45))
    last_ip_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class ExtensionInstallation(Base):
    __tablename__ = "extension_installations"
    __table_args__ = (
        CheckConstraint("launch_count >= 0", name="launch_count_nonnegative"),
        Index("ix_extension_installations_last_seen", "last_seen_at"),
    )

    installation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    extension_version: Mapped[str] = mapped_column(String(32), nullable=False)
    browser_name: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    browser_version: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    platform: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    launch_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    first_seen_at: Mapped[datetime] = created_at_column()
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ExtensionLifecycleEvent(Base):
    __tablename__ = "extension_lifecycle_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('installed','launched','updated')", name="event_type_values"
        ),
        Index("ix_extension_lifecycle_installation", "installation_id", "received_at"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    installation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    extension_version: Mapped[str] = mapped_column(String(32), nullable=False)
    browser_name: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    browser_version: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    platform: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    received_at: Mapped[datetime] = created_at_column()


class VpnSession(Base):
    __tablename__ = "vpn_sessions"
    __table_args__ = (
        CheckConstraint("status IN ('active','ended','error')", name="status_values"),
        CheckConstraint("connection_errors >= 0", name="connection_errors_nonnegative"),
        CheckConstraint("failover_count >= 0", name="failover_count_nonnegative"),
        CheckConstraint("reconnect_count >= 0", name="reconnect_count_nonnegative"),
        CheckConstraint(
            "connection_duration_ms IS NULL OR connection_duration_ms >= 0",
            name="connection_duration_nonnegative",
        ),
        Index("ix_vpn_sessions_user_started", "user_id", "started_at"),
        Index("ix_vpn_sessions_started", "started_at"),
        Index("ix_vpn_sessions_active", "status", "last_seen_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="SET NULL")
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    extension_version: Mapped[str] = mapped_column(String(32), nullable=False)
    browser_name: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    browser_version: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    platform: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    connection_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    connection_duration_ms: Mapped[int | None] = mapped_column(Integer)
    failover_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    reconnect_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    started_at: Mapped[datetime] = created_at_column()
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserActivityEvent(Base):
    __tablename__ = "user_activity_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('connection_attempt','vpn_started','vpn_heartbeat','vpn_stopped',"
            "'connection_error','node_selected','node_failover','reconnect',"
            "'tariff_viewed','payment_link_created')",
            name="event_type_values",
        ),
        CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0", name="duration_nonnegative"
        ),
        Index("ix_user_activity_user_received", "user_id", "received_at"),
        Index("ix_user_activity_type_received", "event_type", "received_at"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="SET NULL")
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64))
    extension_version: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    browser_name: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    browser_version: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    platform: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    received_at: Mapped[datetime] = created_at_column()


class Payment(Base):
    __tablename__ = "payments"
    __table_args__ = (
        CheckConstraint("amount_minor > 0", name="positive_amount"),
        CheckConstraint("period_days > 0", name="positive_period"),
        CheckConstraint("status IN ('created','paid','failed')", name="status_values"),
        CheckConstraint(
            "idempotency_request_hash IS NULL OR idempotency_request_hash ~ '^[0-9a-f]{64}$'",
            name="request_hash_format",
        ),
        CheckConstraint(
            "webhook_hash IS NULL OR webhook_hash ~ '^[0-9a-f]{64}$'",
            name="webhook_hash_format",
        ),
        CheckConstraint(
            "(idempotency_key IS NULL AND idempotency_request_hash IS NULL "
            "AND create_response_json IS NULL) "
            "OR (idempotency_key IS NOT NULL AND idempotency_request_hash IS NOT NULL)",
            name="idempotency_fields_consistent",
        ),
        CheckConstraint(
            "(status = 'paid' AND paid_at IS NOT NULL) OR (status <> 'paid')",
            name="paid_has_timestamp",
        ),
        UniqueConstraint("user_id", "idempotency_key", name="uq_payments_user_idempotency"),
        Index("ix_payments_user_created", "user_id", "created_at"),
        Index("ix_payments_status_created", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    invoice_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    external_payment_id: Mapped[str | None] = mapped_column(String(128))
    tariff_code: Mapped[str] = mapped_column(String(64), nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    period_days: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=PaymentStatus.CREATED.value, server_default="created"
    )
    webhook_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    idempotency_request_hash: Mapped[str | None] = mapped_column(String(64))
    create_response_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class NodeSnapshotAck(Base):
    __tablename__ = "node_snapshot_acks"
    __table_args__ = (
        CheckConstraint("revision ~ '^[0-9a-f]{64}$'", name="revision_format"),
        UniqueConstraint("node_id", "revision", name="uq_node_snapshot_ack_revision"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )
    revision: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_at: Mapped[datetime] = created_at_column()
    response_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class NodeSnapshotIssue(Base):
    __tablename__ = "node_snapshot_issues"
    __table_args__ = (
        CheckConstraint("revision ~ '^[0-9a-f]{64}$'", name="revision_format"),
        UniqueConstraint("node_id", "revision", name="uq_node_snapshot_issue_revision"),
        Index("ix_node_snapshot_issues_expiry", "snapshot_valid_until"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )
    revision: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    issued_at: Mapped[datetime] = created_at_column()


class NodeTelemetryReport(Base):
    __tablename__ = "node_telemetry_reports"
    __table_args__ = (
        CheckConstraint("request_hash ~ '^[0-9a-f]{64}$'", name="request_hash_format"),
        Index("ix_node_telemetry_node_received", "node_id", "received_at"),
    )

    report_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    received_at: Mapped[datetime] = created_at_column()


class NodeUserTraffic(Base):
    __tablename__ = "node_user_traffic"
    __table_args__ = (
        UniqueConstraint("node_id", "user_id", name="uq_node_user_traffic_node_user"),
        CheckConstraint("total_connections >= 0", name="total_connections_nonnegative"),
        CheckConstraint("current_connections >= 0", name="current_connections_nonnegative"),
        CheckConstraint("input_bytes >= 0", name="input_bytes_nonnegative"),
        CheckConstraint("output_bytes >= 0", name="output_bytes_nonnegative"),
        CheckConstraint("total_errors >= 0", name="total_errors_nonnegative"),
        CheckConstraint("connection_seconds >= 0", name="connection_seconds_nonnegative"),
        Index("ix_node_user_traffic_user", "user_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    total_connections: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    current_connections: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    input_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    output_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_errors: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    connection_seconds: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NodeRuntimeMetric(Base):
    __tablename__ = "node_runtime_metrics"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_percent: Mapped[float] = mapped_column(Float, nullable=False)
    disk_percent: Mapped[float] = mapped_column(Float, nullable=False)
    network_rx_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    network_tx_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    gost_up: Mapped[bool] = mapped_column(Boolean, nullable=False)
    sync_agent_up: Mapped[bool] = mapped_column(Boolean, nullable=False)
    tls_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Canary(Base):
    __tablename__ = "canaries"
    __table_args__ = (CheckConstraint("status IN ('active','revoked')", name="status_values"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=CanaryStatus.ACTIVE.value, server_default="active"
    )
    last_report_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class CanaryRun(Base):
    __tablename__ = "canary_runs"
    __table_args__ = (
        CheckConstraint("request_hash ~ '^[0-9a-f]{64}$'", name="request_hash_format"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    canary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("canaries.id", ondelete="CASCADE"), nullable=False
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = created_at_column()


class NodeAuthToken(Base):
    __tablename__ = "node_auth_tokens"
    __table_args__ = (
        CheckConstraint("octet_length(token_hash) = 32", name="token_hash_length"),
        CheckConstraint("status IN ('current','next','revoked')", name="status_values"),
        UniqueConstraint("key_id", "token_hash", name="uq_node_auth_token_hash"),
        Index("ix_node_auth_tokens_lookup", "node_id", "status", "key_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AuthTokenStatus.CURRENT.value, server_default="current"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class CanaryAuthToken(Base):
    __tablename__ = "canary_auth_tokens"
    __table_args__ = (
        CheckConstraint("octet_length(token_hash) = 32", name="token_hash_length"),
        CheckConstraint("status IN ('current','next','revoked')", name="status_values"),
        UniqueConstraint("key_id", "token_hash", name="uq_canary_auth_token_hash"),
        Index("ix_canary_auth_tokens_lookup", "canary_id", "status", "key_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    canary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("canaries.id", ondelete="CASCADE"), nullable=False
    )
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AuthTokenStatus.CURRENT.value, server_default="current"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class NodeCheckEvent(Base):
    __tablename__ = "node_check_events"
    __table_args__ = (
        CheckConstraint("request_hash ~ '^[0-9a-f]{64}$'", name="request_hash_format"),
        Index("ix_node_check_events_node_checked", "node_id", "checked_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    check_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )
    canary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("canaries.id", ondelete="RESTRICT"), nullable=False
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = created_at_column()


class TelegramUpdateEvent(Base):
    __tablename__ = "telegram_update_events"
    __table_args__ = (CheckConstraint("update_id >= 0", name="update_id_nonnegative"),)

    update_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    received_at: Mapped[datetime] = created_at_column()
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_code: Mapped[str] = mapped_column(String(64), nullable=False)


class RateLimitCounter(Base):
    __tablename__ = "rate_limit_counters"
    __table_args__ = (
        CheckConstraint("octet_length(subject_hash) = 32", name="subject_hash_length"),
        CheckConstraint("request_count > 0", name="request_count_positive"),
        Index("ix_rate_limit_counters_window", "window_start"),
    )

    scope: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_hash: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed')",
            name="status_values",
        ),
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        UniqueConstraint("idempotency_key", name="uq_outbox_idempotency_key"),
        Index("ix_outbox_claim", "status", "available_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(100), nullable=False)
    aggregate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=OutboxStatus.PENDING.value, server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = created_at_column()
