from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, update

from vpn_service.app import create_app
from vpn_service.application.device_auth import AuthenticatedDevice
from vpn_service.config import Settings
from vpn_service.persistence.models import Device, Node, User
from vpn_service.security.credentials import ProxyCredentialsCipher
from vpn_service.security.tokens import TokenHasher


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
async def access_client(
    settings_factory: Callable[..., Settings],
    migrated_database: str,
) -> AsyncIterator[tuple[httpx.AsyncClient, object, Settings]]:
    settings = settings_factory(
        database_url=migrated_database,
        status_rate_per_minute=1000,
        nodes_rate_per_minute=1000,
        node_select_rate_per_minute=1000,
        allowed_extension_origins_json=["chrome-extension://abcdefghijklmnopabcdefghijklmnop"],
    )
    app = create_app(settings)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    try:
        async with app.state.database.sessions.begin() as session:
            await session.execute(update(Node).values(status="dead"))
        yield client, app, settings
    finally:
        await client.aclose()
        await app.state.database.dispose()


async def create_node(
    app: object,
    *,
    name: str,
    country_code: str,
    capacity: int = 100,
    status: str = "active",
) -> Node:
    node = Node(
        id=uuid.uuid4(),
        name=f"{name}-{uuid.uuid4()}",
        host=f"{name.lower()}-{uuid.uuid4()}.example.test",
        port=443,
        country_code=country_code,
        provider="test",
        status=status,
        capacity_users=capacity,
    )
    async with app.state.database.sessions.begin() as session:
        session.add(node)
    return node


async def create_bound_device(
    app: object,
    settings: Settings,
    *,
    assigned_node_id: uuid.UUID | None,
    access: str,
    user_status: str = "active",
) -> tuple[uuid.UUID, uuid.UUID, str, str]:
    user_id = uuid.uuid4()
    device_id = uuid.uuid4()
    issued = TokenHasher(settings).issue("device")
    credentials = ProxyCredentialsCipher(settings).generate(user_id)
    now = datetime.now(UTC)
    trial_expires_at = now + timedelta(hours=1) if access == "trial" else now - timedelta(hours=1)
    subscription_expires_at = now + timedelta(days=30) if access == "paid" else None
    async with app.state.database.sessions.begin() as session:
        session.add(
            User(
                id=user_id,
                telegram_id=uuid.uuid4().int % 8_000_000_000 + 10_000_000_000,
                status=user_status,
                trial_expires_at=trial_expires_at,
                subscription_expires_at=subscription_expires_at,
                assigned_node_id=assigned_node_id,
                node_selection_mode="auto",
                proxy_username=credentials.username,
                proxy_password_ciphertext=credentials.password_ciphertext,
                proxy_password_key_id=credentials.key_id,
            )
        )
        await session.flush()
        session.add(
            Device(
                user_id=user_id,
                device_id=device_id,
                device_token_hash=issued.digest,
                device_token_key_id=issued.key_id,
                status="active",
            )
        )
    return user_id, device_id, issued.raw, credentials.password


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_status_enforces_access_and_never_leaks_credentials(
    access_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = access_client
    node = await create_node(app, name="NL", country_code="NL")
    user_id, _device_id, token, expected_password = await create_bound_device(
        app,
        settings,
        assigned_node_id=node.id,
        access="trial",
    )

    response = await client.get("/api/status", headers=bearer(token))
    assert response.status_code == 200
    body = response.json()
    assert body["access"]["state"] == "trial"
    assert body["access"]["can_select_node"] is False
    assert body["vpn"]["available"] is True
    assert body["vpn"]["credentials"]["proxy_password"] == expected_password
    assert body["vpn"]["bypass_list"] == [
        "api-a.example.test",
        "api-b.example.test",
    ]
    assert response.headers["cache-control"] == "no-store"

    async with app.state.database.sessions.begin() as session:
        active_node = await session.get(Node, node.id)
        assert active_node is not None
        active_node.status = "dead"

    unavailable = await client.get("/api/status", headers=bearer(token))
    assert unavailable.status_code == 200
    assert unavailable.json()["vpn"]["unavailable_reason"] == "NO_ACTIVE_NODE"
    assert unavailable.json()["vpn"]["credentials"] is None

    async with app.state.database.sessions.begin() as session:
        user = await session.get(User, user_id)
        assert user is not None
        user.trial_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    expired = await client.get("/api/status", headers=bearer(token))
    assert expired.status_code == 200
    assert expired.json()["vpn"] | {"bypass_list": []} == {
        "available": False,
        "unavailable_reason": "ACCESS_EXPIRED",
        "node": None,
        "credentials": None,
        "bypass_list": [],
    }

    async with app.state.database.sessions.begin() as session:
        user = await session.get(User, user_id)
        assert user is not None
        user.status = "blocked"

    blocked = await client.get("/api/status", headers=bearer(token))
    assert blocked.status_code == 200
    assert blocked.json()["access"]["state"] == "blocked"
    assert blocked.json()["vpn"]["unavailable_reason"] == "USER_BLOCKED"
    assert blocked.json()["vpn"]["credentials"] is None

    async with app.state.database.sessions.begin() as session:
        device = (
            await session.execute(select(Device).where(Device.user_id == user_id))
        ).scalar_one()
        device.status = "revoked"

    revoked = await client.get("/api/status", headers=bearer(token))
    assert revoked.status_code == 401
    assert revoked.json()["error"]["code"] == "DEVICE_REVOKED"

    invalid = await client.get("/api/status", headers=bearer("A" * 43))
    assert invalid.status_code == 401
    assert invalid.json()["error"]["code"] == "INVALID_DEVICE_TOKEN"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_paid_node_list_selection_and_failover_keep_credentials(
    access_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = access_client
    nl = await create_node(app, name="NL", country_code="NL")
    de = await create_node(app, name="DE", country_code="DE")
    user_id, _device_id, token, expected_password = await create_bound_device(
        app,
        settings,
        assigned_node_id=nl.id,
        access="paid",
    )

    listed = await client.get("/api/nodes", headers=bearer(token))
    assert listed.status_code == 200
    assert [item["country_code"] for item in listed.json()["nodes"]] == ["DE", "NL"]
    assert sum(item["selected"] for item in listed.json()["nodes"]) == 1

    selected = await client.post(
        "/api/nodes/select",
        headers=bearer(token),
        json={"node_id": str(de.id)},
    )
    assert selected.status_code == 200
    assert selected.json()["assigned_node"]["id"] == str(de.id)
    assert selected.json()["node_selection_mode"] == "manual"
    assert selected.json()["changed"] is True

    repeated = await client.post(
        "/api/nodes/select",
        headers=bearer(token),
        json={"node_id": str(de.id)},
    )
    assert repeated.status_code == 200
    assert repeated.json()["changed"] is False

    async with app.state.database.sessions.begin() as session:
        node = await session.get(Node, de.id)
        assert node is not None
        node.status = "blocked"

    failed_over = await client.get("/api/status", headers=bearer(token))
    assert failed_over.status_code == 200
    assert failed_over.json()["node_selection_mode"] == "auto"
    assert failed_over.json()["vpn"]["node"]["id"] == str(nl.id)
    assert failed_over.json()["vpn"]["credentials"]["proxy_password"] == expected_password

    async with app.state.database.sessions() as session:
        user = await session.get(User, user_id)
        assert user is not None
        assert user.assigned_node_id == nl.id
        assert user.node_selection_mode == "auto"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_trial_cannot_list_or_select_nodes_and_request_is_strict(
    access_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = access_client
    node = await create_node(app, name="FR", country_code="FR")
    _user_id, _device_id, token, _password = await create_bound_device(
        app,
        settings,
        assigned_node_id=node.id,
        access="trial",
    )

    listed = await client.get("/api/nodes", headers=bearer(token))
    selected = await client.post(
        "/api/nodes/select",
        headers=bearer(token),
        json={"node_id": str(node.id)},
    )
    invalid = await client.post(
        "/api/nodes/select",
        headers=bearer(token),
        json={},
    )
    wrong_media = await client.post(
        "/api/nodes/select",
        headers={**bearer(token), "Content-Type": "text/plain"},
        content="{}",
    )

    assert listed.status_code == 403
    assert listed.json()["error"]["code"] == "PAID_SUBSCRIPTION_REQUIRED"
    assert selected.status_code == 403
    assert selected.json()["error"]["code"] == "PAID_SUBSCRIPTION_REQUIRED"
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "INVALID_REQUEST"
    assert wrong_media.status_code == 415


@pytest.mark.integration
@pytest.mark.asyncio
async def test_101_concurrent_assignments_never_exceed_capacity(
    access_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    _client, app, settings = access_client
    first = await create_node(app, name="A", country_code="NL", capacity=50)
    second = await create_node(app, name="B", country_code="DE", capacity=50)
    identities: list[AuthenticatedDevice] = []
    for _ in range(101):
        user_id, device_id, _token, _password = await create_bound_device(
            app,
            settings,
            assigned_node_id=None,
            access="trial",
        )
        identities.append(
            AuthenticatedDevice(
                device_row_id=uuid.uuid4(),
                device_id=device_id,
                user_id=user_id,
            )
        )

    results = await asyncio.gather(*(app.state.access_service.status(item) for item in identities))
    assert sum(result.node is not None for result in results) == 100
    assert sum(result.node is None for result in results) == 1

    async with app.state.database.sessions() as session:
        counts = dict(
            (
                await session.execute(
                    select(User.assigned_node_id, func.count(User.id))
                    .where(User.assigned_node_id.in_([first.id, second.id]))
                    .group_by(User.assigned_node_id)
                )
            ).all()
        )
    assert counts == {first.id: 50, second.id: 50}
