from __future__ import annotations

import json
import logging

from vpn_service.logging import JsonFormatter, RedactingFilter, redact, sanitize_path


def test_recursive_redaction_removes_sensitive_values() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request Authorization: Bearer visible-token",
        args=(),
        exc_info=None,
    )
    record.event_data = {
        "telegram_bot_token": "visible-telegram-secret",
        "nested": {"proxy_password": "visible-proxy-password"},
        "safe": "kept",
    }

    assert RedactingFilter().filter(record)
    payload = json.loads(JsonFormatter().format(record))
    serialized = json.dumps(payload)

    assert "visible-token" not in serialized
    assert "visible-telegram-secret" not in serialized
    assert "visible-proxy-password" not in serialized
    assert payload["safe"] == "kept"


def test_webhook_secret_is_removed_from_logged_path() -> None:
    path = "/integrations/telegram/webhook/super-secret-path-value"

    sanitized = sanitize_path(path)

    assert sanitized == "/integrations/telegram/webhook/[REDACTED]"
    assert "super-secret" not in sanitized


def test_telegram_start_token_is_removed_from_urls() -> None:
    value = "https://t.me/example_vpn_bot?start=visible-start-token"

    sanitized = redact(value)

    assert sanitized == "https://t.me/example_vpn_bot?start=[REDACTED]"
    assert "visible-start-token" not in sanitized
