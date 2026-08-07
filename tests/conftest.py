from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from vpn_service.config import Settings

TOKEN_KEYS = {
    "device": {"v1": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
    "pairing_session": {"v1": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"},
    "telegram_start": {"v1": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"},
    "node": {"v1": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"},
    "canary": {"v1": "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"},
}
TOKEN_ACTIVE_KEYS = {domain: "v1" for domain in TOKEN_KEYS}
PROXY_KEYS = {"v1": "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"}
PRODUCTION_TOKEN_KEYS = {
    "device": {"v1": "cHJvZC1rZXktMDEtMDEyMzQ1Njc4OWFiY2RlZmdoaWo"},
    "pairing_session": {"v1": "cHJvZC1rZXktMDItMDEyMzQ1Njc4OWFiY2RlZmdoaWo"},
    "telegram_start": {"v1": "cHJvZC1rZXktMDMtMDEyMzQ1Njc4OWFiY2RlZmdoaWo"},
    "node": {"v1": "cHJvZC1rZXktMDQtMDEyMzQ1Njc4OWFiY2RlZmdoaWo"},
    "canary": {"v1": "cHJvZC1rZXktMDUtMDEyMzQ1Njc4OWFiY2RlZmdoaWo"},
}
PRODUCTION_PROXY_KEYS = {"v1": "cHJvZC1rZXktMDYtMDEyMzQ1Njc4OWFiY2RlZmdoaWo"}
TARIFFS = {
    "vpn_30d": {
        "amount_minor": 29_900,
        "period_days": 30,
        "currency": "RUB",
        "enabled": True,
        "description": "Доступ на 30 дней",
    }
}


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    def factory(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "app_env": "test",
            "app_public_base_url": "https://api-a.example.test",
            "public_control_urls_json": [
                "https://api-a.example.test",
                "https://api-b.example.test",
            ],
            "database_url": "postgresql+asyncpg://vpn:test@localhost:5432/vpn_test",
            "token_hash_keyring_json": TOKEN_KEYS,
            "token_hash_active_key_ids_json": TOKEN_ACTIVE_KEYS,
            "proxy_credentials_keyring_json": PROXY_KEYS,
            "proxy_credentials_active_key_id": "v1",
            "tariffs_json": TARIFFS,
            "telegram_bot_token": "test-bot-token-value-at-least-32-chars",
            "telegram_bot_username": "example_vpn_bot",
            "telegram_webhook_public_base_url": "https://bot.example.test",
            "telegram_webhook_secret": "test-webhook-secret-at-least-32-chars",
            "telegram_webhook_path_secret": "test-path-secret-value-at-least-32-chars",
        }
        if overrides.get("app_env") == "production":
            values.update(
                {
                    "app_public_base_url": "https://api-a.vpn.example",
                    "public_control_urls_json": [
                        "https://api-a.vpn.example",
                        "https://api-b.vpn.example",
                    ],
                    "database_url": (
                        "postgresql+asyncpg://vpn:production-password@postgres:5432/vpn"
                    ),
                    "token_hash_keyring_json": PRODUCTION_TOKEN_KEYS,
                    "proxy_credentials_keyring_json": PRODUCTION_PROXY_KEYS,
                    "telegram_bot_token": "123456789:production-bot-token-material",
                    "telegram_bot_username": "vpn_service_bot",
                    "telegram_webhook_public_base_url": "https://bot.vpn.example",
                    "telegram_webhook_secret": "production-webhook-secret-material-01",
                    "telegram_webhook_path_secret": "production-webhook-path-material-01",
                    "allowed_extension_origins_json": [
                        "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
                    ],
                }
            )
        values.update(overrides)
        return Settings(**values)

    return factory
