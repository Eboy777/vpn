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
            "telegram_channel_url": "https://t.me/example_vpn_channel",
            "telegram_support_username": "example_vpn_support",
            "chrome_web_store_url": "https://chromewebstore.google.com/",
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
                    "telegram_channel_url": "https://t.me/vpn_service_channel",
                    "telegram_support_username": "vpn_service_support",
                    "chrome_web_store_url": (
                        "https://chromewebstore.google.com/detail/virgo/"
                        "abcdefghijklmnopabcdefghijklmnop"
                    ),
                    "allowed_extension_origins_json": [
                        "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
                    ],
                    "trusted_proxy_cidrs": ["10.77.0.2/32", "10.77.0.3/32"],
                    "admin_panel_enabled": True,
                    "admin_panel_password_hash": (
                        "pbkdf2_sha256$600000$80_7LWPZHysGYakg4MzyaQ$"
                        "IyhJ6E2INrWAIk-_wkLCbr2KIx18cBbx_Fn5o49R09Y"
                    ),
                    "admin_telegram_bot_token": ("production-admin-bot-token-material-0001"),
                    "admin_telegram_chat_ids_json": [1000000001],
                    "metrics_scrape_token": "production-metrics-token-material-0001",
                }
            )
        values.update(overrides)
        return Settings(**values)

    return factory
