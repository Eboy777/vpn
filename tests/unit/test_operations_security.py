from __future__ import annotations

import base64
from collections.abc import Callable

import httpx
import pytest

from vpn_service.app import create_app
from vpn_service.config import Settings
from vpn_service.external.admin_telegram import _render_alert
from vpn_service.security.admin_password import hash_admin_password, verify_admin_password


def test_admin_password_hash_is_salted_and_verifiable() -> None:
    first = hash_admin_password("a-strong-admin-password")
    second = hash_admin_password("a-strong-admin-password")

    assert first != second
    assert "a-strong-admin-password" not in first
    assert verify_admin_password("a-strong-admin-password", first) is True
    assert verify_admin_password("wrong-admin-password", first) is False


@pytest.mark.asyncio
async def test_admin_panel_requires_password_and_serves_no_store_assets(
    settings_factory: Callable[..., Settings],
) -> None:
    password = "test-admin-password-123"
    settings = settings_factory(
        admin_panel_enabled=True,
        admin_panel_password_hash=hash_admin_password(password),
    )
    app = create_app(settings, database_probe=lambda: None)  # type: ignore[arg-type]
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    try:
        missing = await client.get("/admin")
        quality_missing = await client.get("/admin/api/quality")
        wrong = await client.get("/admin", auth=("admin", "wrong-admin-password"))
        accepted = await client.get("/admin", auth=("admin", password))
    finally:
        await client.aclose()

    assert missing.status_code == 401
    assert quality_missing.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert accepted.headers["cache-control"] == "no-store"
    assert "Virgo" in accepted.text


@pytest.mark.asyncio
async def test_metrics_endpoint_requires_independent_bearer_secret(
    settings_factory: Callable[..., Settings],
) -> None:
    token = "M" * 43
    app = create_app(settings_factory(metrics_scrape_token=token), database_probe=lambda: None)  # type: ignore[arg-type]
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    try:
        missing = await client.get("/internal/metrics")
        invalid = await client.get(
            "/internal/metrics", headers={"Authorization": "Bearer " + "X" * 43}
        )
        valid = await client.get("/internal/metrics", headers={"Authorization": "Bearer " + token})
    finally:
        await client.aclose()

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert valid.status_code == 503


def test_admin_alert_renderer_uses_only_allowlisted_safe_fields() -> None:
    rendered = _render_alert(
        {
            "event": "node_health_warning",
            "data": {
                "node_name": "NL-1\nforged",
                "node_id": "node-id",
                "problem": "disk_high",
                "value": "91.2%",
                "secret": base64.b64encode(b"must-not-appear").decode(),
            },
        }
    )

    assert "NL-1 forged" in rendered
    assert "disk_high" in rendered
    assert "91.2%" in rendered
    assert "must-not-appear" not in rendered


def test_admin_alert_renderer_supports_control_ingress_failures() -> None:
    failed = _render_alert(
        {
            "event": "control_ingress_failed",
            "data": {
                "url": "https://api-a.example",
                "error_code": "TIMEOUT",
                "attempts": 3,
            },
        }
    )
    recovered = _render_alert(
        {
            "event": "control_ingress_recovered",
            "data": {"url": "https://api-a.example"},
        }
    )

    assert "недоступен из России" in failed
    assert "TIMEOUT" in failed
    assert "снова доступен" in recovered
