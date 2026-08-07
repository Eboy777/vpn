from __future__ import annotations

import argparse
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, update

from vpn_service.admin_cli import (
    _activate_node,
    _finalize_node_drain,
    _issue_node_token,
    _prepare_node_drain,
    _promote_node_token,
    _revoke_node_token,
)
from vpn_service.app import create_app
from vpn_service.config import Settings
from vpn_service.node_agent.agent import NodeSyncAgent
from vpn_service.node_agent.config import NodeAgentSettings
from vpn_service.persistence.models import (
    Node,
    NodeAuthToken,
    NodeSnapshotAck,
    NodeSnapshotIssue,
    User,
)
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
async def node_client(
    settings_factory: Callable[..., Settings],
    migrated_database: str,
) -> AsyncIterator[tuple[httpx.AsyncClient, object, Settings]]:
    settings = settings_factory(
        database_url=migrated_database,
        internal_api_rate_per_minute=1000,
        node_credential_snapshot_ttl_seconds=300,
    )
    app = create_app(settings)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    try:
        async with app.state.database.sessions.begin() as session:
            await session.execute(update(Node).values(status="dead"))
            await session.execute(update(User).values(status="blocked"))
            await session.execute(update(NodeAuthToken).values(status="revoked"))
        yield client, app, settings
    finally:
        await client.aclose()
        await app.state.database.dispose()


async def create_node_identity(
    app: object,
    settings: Settings,
    *,
    status: str = "active",
    token_status: str = "current",
    token_expires_at: datetime | None = None,
) -> tuple[Node, str]:
    node = Node(
        id=uuid.uuid4(),
        name=f"NODE-{uuid.uuid4()}",
        host=f"node-{uuid.uuid4()}.example.test",
        port=443,
        country_code="NL",
        provider="test",
        status=status,
        capacity_users=100,
    )
    issued = TokenHasher(settings).issue("node")
    async with app.state.database.sessions.begin() as session:
        session.add(node)
        await session.flush()
        session.add(
            NodeAuthToken(
                node_id=node.id,
                key_id=issued.key_id,
                token_hash=issued.digest,
                status=token_status,
                expires_at=token_expires_at,
            )
        )
    return node, issued.raw


async def create_user(
    app: object,
    settings: Settings,
    *,
    username_sort: int,
    access: str,
    status: str = "active",
    assigned_node_id: uuid.UUID | None = None,
) -> tuple[User, str]:
    user_id = uuid.uuid4()
    generated = ProxyCredentialsCipher(settings).generate(user_id)
    unique_suffix = uuid.uuid4().int % (10**24)
    username = f"u_{username_sort:02d}{unique_suffix:024d}"
    now = datetime.now(UTC)
    trial = now + timedelta(hours=1) if access == "trial" else now - timedelta(hours=1)
    subscription = now + timedelta(days=30) if access == "paid" else None
    user = User(
        id=user_id,
        telegram_id=uuid.uuid4().int % 8_000_000_000 + 20_000_000_000,
        status=status,
        trial_expires_at=trial,
        subscription_expires_at=subscription,
        assigned_node_id=assigned_node_id,
        proxy_username=username,
        proxy_password_ciphertext=generated.password_ciphertext,
        proxy_password_key_id=generated.key_id,
    )
    async with app.state.database.sessions.begin() as session:
        session.add(user)
    return user, generated.password


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_snapshot_filters_sorts_and_supports_etag_and_idempotent_ack(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = node_client
    node, token = await create_node_identity(app, settings)
    paid, paid_password = await create_user(app, settings, username_sort=2, access="paid")
    trial, trial_password = await create_user(app, settings, username_sort=1, access="trial")
    await create_user(app, settings, username_sort=3, access="expired")
    await create_user(app, settings, username_sort=4, access="paid", status="blocked")

    response = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "node_id",
        "node_status",
        "generated_at",
        "snapshot_valid_until",
        "revision",
        "credentials",
    }
    assert [item["proxy_username"] for item in body["credentials"]] == [
        trial.proxy_username,
        paid.proxy_username,
    ]
    assert [item["proxy_password"] for item in body["credentials"]] == [
        trial_password,
        paid_password,
    ]
    assert response.headers["etag"] == f'"sha256:{body["revision"]}"'
    assert response.headers["x-snapshot-generated-at"] == body["generated_at"]
    assert response.headers["x-snapshot-valid-until"] == body["snapshot_valid_until"]
    assert response.headers["cache-control"] == "no-store"

    not_modified = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers={**auth(token), "If-None-Match": response.headers["etag"]},
    )
    assert not_modified.status_code == 304
    assert not not_modified.content
    assert "content-type" not in not_modified.headers
    assert not_modified.headers["etag"] == response.headers["etag"]

    ack = await client.post(
        f"/internal/nodes/{node.id}/credentials/ack",
        headers=auth(token),
        json={"revision": body["revision"]},
    )
    replay = await client.post(
        f"/internal/nodes/{node.id}/credentials/ack",
        headers=auth(token),
        json={"revision": body["revision"]},
    )
    assert ack.status_code == 200
    assert replay.status_code == 200
    assert replay.content == ack.content

    async with app.state.database.sessions() as session:
        stored = await session.get(Node, node.id)
        assert stored is not None
        assert stored.applied_credentials_revision == body["revision"]
        ack_count = await session.scalar(
            select(func.count(NodeSnapshotAck.id)).where(NodeSnapshotAck.node_id == node.id)
        )
        assert ack_count == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_node_token_scope_status_and_strict_contract(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = node_client
    first, first_token = await create_node_identity(app, settings)
    second, second_token = await create_node_identity(app, settings)

    mismatch = await client.get(
        f"/internal/nodes/{second.id}/credentials",
        headers=auth(first_token),
    )
    invalid = await client.get(
        f"/internal/nodes/{first.id}/credentials",
        headers=auth("A" * 43),
    )
    invalid_id = await client.get(
        "/internal/nodes/not-a-uuid/credentials",
        headers=auth(first_token),
    )
    invalid_etag = await client.get(
        f"/internal/nodes/{first.id}/credentials",
        headers={**auth(first_token), "If-None-Match": "weak"},
    )
    wrong_media = await client.post(
        f"/internal/nodes/{first.id}/credentials/ack",
        headers={**auth(first_token), "Content-Type": "text/plain"},
        content="{}",
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["error"]["code"] == "NODE_TOKEN_MISMATCH"
    assert invalid.status_code == 401
    assert invalid.json()["error"]["code"] == "INVALID_NODE_TOKEN"
    assert invalid_id.status_code == 400
    assert invalid_id.json()["error"]["code"] == "INVALID_NODE_ID"
    assert invalid_etag.status_code == 400
    assert wrong_media.status_code == 415

    async with app.state.database.sessions.begin() as session:
        token_row = (
            await session.execute(select(NodeAuthToken).where(NodeAuthToken.node_id == second.id))
        ).scalar_one()
        token_row.status = "revoked"
    revoked = await client.get(
        f"/internal/nodes/{second.id}/credentials",
        headers=auth(second_token),
    )
    assert revoked.status_code == 401

    async with app.state.database.sessions.begin() as session:
        node = await session.get(Node, first.id)
        assert node is not None
        node.status = "dead"
    dead = await client.get(
        f"/internal/nodes/{first.id}/credentials",
        headers=auth(first_token),
    )
    assert dead.status_code == 409
    assert dead.json()["error"]["code"] == "NODE_DEAD"


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["blocked", "draining"])
async def test_non_active_snapshot_is_always_empty_and_ignores_etag(
    node_client: tuple[httpx.AsyncClient, object, Settings],
    status: str,
) -> None:
    client, app, settings = node_client
    node, token = await create_node_identity(app, settings, status=status)
    await create_user(app, settings, username_sort=10, access="paid")
    response = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers={**auth(token), "If-None-Match": f'"sha256:{"0" * 64}"'},
    )
    assert response.status_code == 200
    assert response.json()["node_status"] == status
    assert response.json()["credentials"] == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_warming_node_receives_credentials_without_becoming_assignable(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = node_client
    node, token = await create_node_identity(app, settings, status="warming")
    user, _password = await create_user(app, settings, username_sort=11, access="trial")
    response = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(token),
    )
    assert response.status_code == 200
    assert response.json()["node_status"] == "warming"
    assert [item["proxy_username"] for item in response.json()["credentials"]] == [
        user.proxy_username
    ]
    with pytest.raises(RuntimeError, match="fresh applied snapshot"):
        await _activate_node(app.state.database, argparse.Namespace(node_id=str(node.id)))
    acknowledged = await client.post(
        f"/internal/nodes/{node.id}/credentials/ack",
        headers=auth(token),
        json={"revision": response.json()["revision"]},
    )
    assert acknowledged.status_code == 200
    activated = await _activate_node(
        app.state.database,
        argparse.Namespace(node_id=str(node.id)),
    )
    assert activated == {"node_id": str(node.id), "status": "active"}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_planned_drain_reassigns_before_empty_snapshot(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = node_client
    source, source_token = await create_node_identity(app, settings, status="active")
    target, _target_token = await create_node_identity(app, settings, status="active")
    user, _password = await create_user(
        app,
        settings,
        username_sort=12,
        access="paid",
        assigned_node_id=source.id,
    )
    prepared = await _prepare_node_drain(
        app.state.database,
        settings,
        argparse.Namespace(node_id=str(source.id)),
    )
    assert prepared["status"] == "quiescing"
    assert prepared["reassigned_users"] == 1
    assert prepared["users_without_capacity"] == 0
    async with app.state.database.sessions() as session:
        stored_user = await session.get(User, user.id)
        assert stored_user is not None
        assert stored_user.assigned_node_id == target.id

    quiescing = await client.get(
        f"/internal/nodes/{source.id}/credentials",
        headers=auth(source_token),
    )
    assert quiescing.status_code == 200
    assert quiescing.json()["node_status"] == "quiescing"
    assert quiescing.json()["credentials"]

    finalized = await _finalize_node_drain(
        app.state.database,
        argparse.Namespace(node_id=str(source.id)),
    )
    assert finalized == {"node_id": str(source.id), "status": "draining"}
    draining = await client.get(
        f"/internal/nodes/{source.id}/credentials",
        headers=auth(source_token),
    )
    assert draining.status_code == 200
    assert draining.json()["credentials"] == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_node_token_two_phase_rotation(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = node_client
    node, old_token = await create_node_identity(app, settings, status="active")
    issued = await _issue_node_token(
        app.state.database,
        settings,
        argparse.Namespace(node_id=str(node.id), status="next"),
    )
    new_token = str(issued["node_credentials_token"])
    token_id = str(issued["token_id"])
    assert len(new_token) == 43
    old_before = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(old_token),
    )
    next_before = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(new_token),
    )
    assert old_before.status_code == 200
    assert next_before.status_code == 200

    await _promote_node_token(
        app.state.database,
        argparse.Namespace(node_id=str(node.id), token_id=token_id),
    )
    old_after = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(old_token),
    )
    new_after = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(new_token),
    )
    assert old_after.status_code == 401
    assert new_after.status_code == 200

    await _revoke_node_token(
        app.state.database,
        argparse.Namespace(node_id=str(node.id), token_id=token_id),
    )
    revoked = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(new_token),
    )
    assert revoked.status_code == 401


@pytest.mark.integration
@pytest.mark.asyncio
async def test_drain_cannot_finalize_without_reassignment_capacity(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    _client, app, settings = node_client
    source, _token = await create_node_identity(app, settings, status="active")
    user, _password = await create_user(
        app,
        settings,
        username_sort=13,
        access="trial",
        assigned_node_id=source.id,
    )
    prepared = await _prepare_node_drain(
        app.state.database,
        settings,
        argparse.Namespace(node_id=str(source.id)),
    )
    assert prepared["reassigned_users"] == 0
    assert prepared["users_without_capacity"] == 1
    async with app.state.database.sessions() as session:
        stored = await session.get(User, user.id)
        assert stored is not None
        assert stored.assigned_node_id == source.id
    with pytest.raises(RuntimeError, match="still assigned"):
        await _finalize_node_drain(
            app.state.database,
            argparse.Namespace(node_id=str(source.id)),
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unknown_and_expired_snapshot_ack_are_rejected(
    node_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = node_client
    node, token = await create_node_identity(app, settings)
    snapshot = await client.get(
        f"/internal/nodes/{node.id}/credentials",
        headers=auth(token),
    )
    revision = snapshot.json()["revision"]
    unknown = await client.post(
        f"/internal/nodes/{node.id}/credentials/ack",
        headers=auth(token),
        json={"revision": "f" * 64},
    )
    assert unknown.status_code == 409
    assert unknown.json()["error"]["code"] == "SNAPSHOT_REVISION_UNKNOWN"

    async with app.state.database.sessions.begin() as session:
        issue = (
            await session.execute(
                select(NodeSnapshotIssue).where(
                    NodeSnapshotIssue.node_id == node.id,
                    NodeSnapshotIssue.revision == revision,
                )
            )
        ).scalar_one()
        issue.snapshot_valid_until = datetime.now(UTC) - timedelta(seconds=1)
    expired = await client.post(
        f"/internal/nodes/{node.id}/credentials/ack",
        headers=auth(token),
        json={"revision": revision},
    )
    assert expired.status_code == 409
    assert expired.json()["error"]["code"] == "SNAPSHOT_LEASE_EXPIRED"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_backend_to_agent_component_flow_applies_and_acknowledges(
    node_client: tuple[httpx.AsyncClient, object, Settings],
    tmp_path: Path,
) -> None:
    client, app, settings = node_client
    node, token = await create_node_identity(app, settings)
    user, password = await create_user(app, settings, username_sort=20, access="trial")
    agent_settings = NodeAgentSettings(
        control_api_base_url="https://primary.example.test",
        node_id=node.id,
        node_credentials_token=token,
        node_sync_state_path=tmp_path / "state.json",
        gost_config_path=tmp_path / "auth.txt",
        gost_config_staging_path=tmp_path / "auth.staging",
        gost_canary_proxy_username="canary_component",
        gost_canary_proxy_password="C" * 32,
        gost_canary_credential_version="v1",
    )

    async def command_succeeds(_command: tuple[str, ...], _timeout: float) -> None:
        return None

    agent = NodeSyncAgent(
        agent_settings,
        client=client,
        command_runner=command_succeeds,
    )
    await agent.sync_once()
    auth_file = agent_settings.gost_config_path.read_text()
    assert f"{user.proxy_username} {password}" in auth_file
    assert "canary_component " + "C" * 32 in auth_file

    async with app.state.database.sessions() as session:
        stored = await session.get(Node, node.id)
        assert stored is not None
        assert stored.credentials_revision is not None
        assert stored.applied_credentials_revision == stored.credentials_revision
        assert stored.last_sync_at is not None
