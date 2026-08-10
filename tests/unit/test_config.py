from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy

import pytest
from pydantic import ValidationError

from tests.conftest import TARIFFS, TOKEN_ACTIVE_KEYS, TOKEN_KEYS
from vpn_service.config import AppEnvironment, Settings


def test_valid_settings_load_and_hide_secrets(settings_factory: Callable[..., Settings]) -> None:
    settings = settings_factory()

    assert settings.app_env is AppEnvironment.TEST
    assert settings.device_limit_per_user == 3
    assert settings.database_url.get_secret_value().startswith("postgresql+asyncpg://")
    assert "test@localhost" not in str(settings.database_url)


def test_rejects_reused_token_key_material(settings_factory: Callable[..., Settings]) -> None:
    keyring = deepcopy(TOKEN_KEYS)
    keyring["canary"]["v1"] = keyring["node"]["v1"]

    with pytest.raises(ValidationError, match="must not reuse key material"):
        settings_factory(token_hash_keyring_json=keyring)


def test_rejects_missing_active_key(settings_factory: Callable[..., Settings]) -> None:
    active = dict(TOKEN_ACTIVE_KEYS)
    active["device"] = "v2"

    with pytest.raises(ValidationError, match="active token key device.v2 does not exist"):
        settings_factory(token_hash_active_key_ids_json=active)


def test_rejects_non_async_postgres_dsn(settings_factory: Callable[..., Settings]) -> None:
    with pytest.raises(ValidationError, match=r"must use postgresql\+asyncpg"):
        settings_factory(database_url="sqlite+aiosqlite://")


def test_rejects_changed_mvp_tariff(settings_factory: Callable[..., Settings]) -> None:
    tariffs = deepcopy(TARIFFS)
    tariffs["vpn_30d"]["amount_minor"] = 30_000

    with pytest.raises(ValidationError, match="vpn_30d does not match"):
        settings_factory(tariffs_json=tariffs)


def test_rejects_missing_approved_tariff(settings_factory: Callable[..., Settings]) -> None:
    tariffs = deepcopy(TARIFFS)
    tariffs.pop("vpn_15d")

    with pytest.raises(ValidationError, match="exactly vpn_15d and vpn_30d"):
        settings_factory(tariffs_json=tariffs)


def test_production_profile_accepts_only_approved_values(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(app_env="production")

    assert settings.app_env is AppEnvironment.PRODUCTION
    assert settings.payments_production_enabled is False


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"device_limit_per_user": 4}, "device limit must be 3"),
        ({"pairing_init_rate_per_minute": 11}, "rate limits must match"),
        ({"status_rate_per_minute": 121}, "access endpoint limits must match"),
        ({"internal_api_rate_per_minute": 121}, "snapshot settings must match"),
        ({"node_block_failure_threshold": 2}, "thresholds must be 3 failures"),
        ({"telegram_delivery_mode": "polling"}, "delivery mode must be webhook"),
        ({"admin_panel_enabled": False}, "password-protected admin panel"),
        ({"admin_telegram_chat_ids_json": []}, "separate admin Telegram bot"),
        ({"metrics_scrape_token": None}, "strong metrics scrape token"),
        ({"discovery_signing_private_key": None}, "DISCOVERY_SIGNING_PRIVATE_KEY"),
        ({"payments_production_enabled": True}, "production payments remain disabled"),
        ({"robokassa_is_test": False}, "must remain in test mode"),
        (
            {"telegram_webhook_secret": "replace-with-32-character-secret-value"},
            "contains a development placeholder",
        ),
        (
            {"public_control_urls_json": ["https://api-a.example.test"]},
            "at least two distinct control URLs",
        ),
        (
            {
                "public_control_urls_json": [
                    "https://api-a.vpn.example",
                    "https://api-a.vpn.example:8443",
                ]
            },
            "two distinct hostnames",
        ),
        (
            {"trusted_proxy_cidrs": ["10.77.0.0/24", "10.78.0.3/32"]},
            "must use exact host CIDRs",
        ),
        (
            {"trusted_proxy_cidrs": ["10.77.0.2/32"]},
            "exactly two API proxy peer addresses",
        ),
        (
            {"trusted_proxy_cidrs": ["10.77.0.2/32", "10.77.0.2/32"]},
            "exactly two API proxy peer addresses",
        ),
        (
            {"trusted_proxy_cidrs": ["127.0.0.1/32", "10.77.0.3/32"]},
            "must be private WireGuard peer addresses",
        ),
    ],
)
def test_production_profile_rejects_unsafe_values(
    settings_factory: Callable[..., Settings],
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        settings_factory(app_env="production", **overrides)
