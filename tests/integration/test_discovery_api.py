from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete

from vpn_service.app import create_app
from vpn_service.config import Settings
from vpn_service.persistence.models import ControlIngress
from vpn_service.security.admin_password import hash_admin_password


def database_url() -> str:
    import os

    value = os.environ.get("TEST_DATABASE_URL")
    if not value:
        pytest.skip("TEST_DATABASE_URL is not configured")
    return value


@pytest.fixture(scope="module", autouse=True)
def migrated_database() -> str:
    url = database_url()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(config, "head")
    return url


@pytest.fixture
async def discovery_client(
    settings_factory: Callable[..., Settings],
    migrated_database: str,
) -> AsyncIterator[tuple[httpx.AsyncClient, object, str]]:
    password = "test-discovery-admin-password"
    settings = settings_factory(
        database_url=migrated_database,
        admin_panel_enabled=True,
        admin_panel_password_hash=hash_admin_password(password),
        discovery_signing_private_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI",
    )
    app = create_app(settings)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    try:
        async with app.state.database.sessions.begin() as session:
            await session.execute(delete(ControlIngress))
        yield client, app, password
    finally:
        await client.aclose()
        await app.state.database.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_admin_manages_signed_discovery_addresses(discovery_client) -> None:
    client, _app, password = discovery_client
    auth = httpx.BasicAuth("admin", password)
    action_headers = {"X-Admin-Action": "1"}

    initial = await client.get("/api/discovery/control-ingresses")
    created = await client.post(
        "/admin/api/ingresses",
        auth=auth,
        headers=action_headers,
        json={"url": "https://api-reserve.example", "priority": 10},
    )
    after_add = await client.get("/api/discovery/control-ingresses")
    ingress_id = created.json()["id"]
    disabled = await client.post(
        f"/admin/api/ingresses/{ingress_id}/update",
        auth=auth,
        headers=action_headers,
        json={"enabled": False, "priority": 10},
    )
    after_disable = await client.get("/api/discovery/control-ingresses")
    removed = await client.post(
        f"/admin/api/ingresses/{ingress_id}/delete",
        auth=auth,
        headers=action_headers,
        json={},
    )

    assert initial.status_code == 200
    assert len(initial.json()["control_urls"]) == 2
    assert created.status_code == 200
    assert after_add.json()["control_urls"][-1] == "https://api-reserve.example"
    assert disabled.json()["enabled"] is False
    assert len(after_disable.json()["control_urls"]) == 2
    assert removed.json() == {"deleted": True, "id": ingress_id}
