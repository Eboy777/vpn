from vpn_service.persistence import models  # noqa: F401
from vpn_service.persistence.base import Base


def test_stage_one_metadata_contains_expected_tables() -> None:
    assert set(Base.metadata.tables) == {
        "canaries",
        "canary_auth_tokens",
        "devices",
        "node_auth_tokens",
        "node_check_events",
        "node_snapshot_acks",
        "nodes",
        "outbox_events",
        "payments",
        "telegram_update_events",
        "users",
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
