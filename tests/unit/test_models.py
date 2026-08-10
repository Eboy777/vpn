from vpn_service.persistence import models  # noqa: F401
from vpn_service.persistence.base import Base


def test_stage_one_metadata_contains_expected_tables() -> None:
    assert set(Base.metadata.tables) == {
        "canaries",
        "canary_auth_tokens",
        "canary_runs",
        "devices",
        "extension_installations",
        "extension_lifecycle_events",
        "node_auth_tokens",
        "node_check_events",
        "node_runtime_metrics",
        "node_snapshot_acks",
        "node_snapshot_issues",
        "node_telemetry_reports",
        "node_user_traffic",
        "nodes",
        "outbox_events",
        "payments",
        "rate_limit_counters",
        "telegram_update_events",
        "user_activity_events",
        "users",
        "vpn_sessions",
    }


def test_sensitive_columns_are_hashes_or_ciphertext() -> None:
    columns = {
        f"{table.name}.{column.name}"
        for table in Base.metadata.tables.values()
        for column in table.columns
    }

    assert "devices.device_token" not in columns
    assert "devices.telegram_start_token" not in columns
    assert "devices.pairing_session_token" not in columns
    assert "users.proxy_password" not in columns
    assert "users.proxy_password_ciphertext" in columns
    assert "node_auth_tokens.token_hash" in columns
    assert "canary_auth_tokens.token_hash" in columns


def test_quality_analytics_columns_are_present() -> None:
    columns = {
        f"{table.name}.{column.name}"
        for table in Base.metadata.tables.values()
        for column in table.columns
    }

    assert "vpn_sessions.connection_duration_ms" in columns
    assert "vpn_sessions.failover_count" in columns
    assert "vpn_sessions.reconnect_count" in columns
    assert "user_activity_events.browser_version" in columns
    assert "user_activity_events.platform" in columns
