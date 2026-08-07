from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from vpn_service.app import create_app
from vpn_service.config import Settings


@pytest.mark.asyncio
async def test_liveness_does_not_touch_database(
    settings_factory: Callable[..., Settings],
) -> None:
    calls = 0

    async def probe() -> bool:
        nonlocal calls
        calls += 1
        return True

    app = create_app(settings_factory(), database_probe=probe)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["content-type"] == "application/json"
    assert response.headers["x-request-id"]
    assert calls == 0


@pytest.mark.asyncio
async def test_readiness_reports_database_ready(
    settings_factory: Callable[..., Settings],
) -> None:
    async def probe() -> bool:
        return True

    app = create_app(settings_factory(), database_probe=probe)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/health/ready", headers={"X-Request-ID": "9dd7596a-16c3-47a6-b80e-f25f674c9164"}
        )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
    assert response.headers["x-request-id"] == "9dd7596a-16c3-47a6-b80e-f25f674c9164"


@pytest.mark.asyncio
@pytest.mark.parametrize("probe_mode", ["false", "error"])
async def test_readiness_reports_database_unavailable(
    settings_factory: Callable[..., Settings], probe_mode: str
) -> None:
    async def probe() -> bool:
        if probe_mode == "error":
            raise RuntimeError("database-password-must-not-leak")
        return False

    app = create_app(settings_factory(), database_probe=probe)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "unavailable"}
    assert "password" not in response.text


@pytest.mark.asyncio
async def test_undocumented_framework_endpoints_are_disabled(
    settings_factory: Callable[..., Settings],
) -> None:
    async def probe() -> bool:
        return True

    app = create_app(settings_factory(), database_probe=probe)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            response = await client.get(path)
            assert response.status_code == 404
