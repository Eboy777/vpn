from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from vpn_service.node_agent.agent import NodeSyncAgent
from vpn_service.node_agent.config import NodeAgentSettings
from vpn_service.node_agent.models import AgentState
from vpn_service.node_agent.storage import AtomicFiles


def settings(tmp_path: Path, node_id: uuid.UUID) -> NodeAgentSettings:
    return NodeAgentSettings(
        control_api_base_url="https://primary.example.test",
        control_api_fallback_urls_json=["https://fallback.example.test"],
        node_id=node_id,
        node_credentials_token="N" * 43,
        node_sync_state_path=tmp_path / "state.json",
        gost_config_path=tmp_path / "auth.txt",
        gost_config_staging_path=tmp_path / "auth.staging",
        gost_canary_proxy_username="canary_node_1",
        gost_canary_proxy_password="C" * 32,
        gost_canary_credential_version="v1",
    )


def snapshot_body(node_id: uuid.UUID) -> tuple[dict[str, object], dict[str, str]]:
    generated = datetime(2026, 8, 7, 10, 0, tzinfo=UTC)
    valid_until = generated + timedelta(minutes=5)
    credential_valid_until = generated + timedelta(hours=1)
    credentials = [
        {
            "proxy_username": "u_" + "0" * 26,
            "proxy_password": "P" * 32,
            "valid_until": _format(credential_valid_until),
        }
    ]
    canonical = {"node_status": "active", "credentials": credentials}
    revision = hashlib.sha256(
        json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    body: dict[str, object] = {
        "node_id": str(node_id),
        "node_status": "active",
        "generated_at": _format(generated),
        "snapshot_valid_until": _format(valid_until),
        "revision": revision,
        "credentials": credentials,
    }
    headers = {
        "ETag": f'"sha256:{revision}"',
        "X-Snapshot-Generated-At": _format(generated),
        "X-Snapshot-Valid-Until": _format(valid_until),
    }
    return body, headers


async def successful_command(_command: tuple[str, ...], _timeout: float) -> None:
    return None


def test_agent_settings_reject_short_canary_password(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="canary password"):
        NodeAgentSettings(
            control_api_base_url="https://primary.example.test",
            node_id=uuid.uuid4(),
            node_credentials_token="N" * 43,
            node_sync_state_path=tmp_path / "state.json",
            gost_config_path=tmp_path / "auth.txt",
            gost_config_staging_path=tmp_path / "auth.staging",
            gost_canary_proxy_username="canary",
            gost_canary_proxy_password="short",
            gost_canary_credential_version="v1",
        )


def test_agent_settings_require_http_timeout_beyond_long_poll(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="timeout must exceed long poll"):
        NodeAgentSettings(
            control_api_base_url="https://primary.example.test",
            node_id=uuid.uuid4(),
            node_credentials_token="N" * 43,
            node_sync_timeout_seconds=20,
            node_long_poll_wait_seconds=20,
            node_sync_state_path=tmp_path / "state.json",
            gost_config_path=tmp_path / "auth.txt",
            gost_config_staging_path=tmp_path / "auth.staging",
            gost_canary_proxy_username="canary",
            gost_canary_proxy_password="C" * 32,
            gost_canary_credential_version="v1",
        )


@pytest.mark.asyncio
async def test_agent_atomically_applies_snapshot_and_acknowledges(tmp_path: Path) -> None:
    node_id = uuid.uuid4()
    config = settings(tmp_path, node_id)
    body, headers = snapshot_body(node_id)
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, headers=headers, json=body)
        return httpx.Response(
            200,
            json={
                "processed": True,
                "node_id": str(node_id),
                "revision": body["revision"],
                "applied_at": "2026-08-07T10:00:01.000Z",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    agent = NodeSyncAgent(config, client=client, command_runner=successful_command)
    await agent.sync_once()
    await client.aclose()

    auth_file = config.gost_config_path.read_text()
    assert "canary_node_1 " + "C" * 32 in auth_file
    assert "u_" + "0" * 26 + " " + "P" * 32 in auth_file
    state = AtomicFiles(
        config.gost_config_path,
        config.gost_config_staging_path,
        config.node_sync_state_path,
    ).load_state()
    assert state.revision == body["revision"]
    assert state.ack_pending is False
    assert state.failed_closed is False
    assert [request.method for request in requests] == ["GET", "POST"]
    assert all(request.headers["authorization"] == "Bearer " + "N" * 43 for request in requests)
    assert requests[0].url.params["wait_seconds"] == "20"


@pytest.mark.asyncio
async def test_invalid_snapshot_does_not_replace_working_auth(tmp_path: Path) -> None:
    node_id = uuid.uuid4()
    config = settings(tmp_path, node_id)
    config.gost_config_path.write_bytes(b"working-auth\n")
    body, headers = snapshot_body(node_id)
    body["revision"] = "f" * 64
    headers["ETag"] = f'"sha256:{body["revision"]}"'

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers, json=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    agent = NodeSyncAgent(config, client=client, command_runner=successful_command)
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        await agent.sync_once()
    await client.aclose()
    assert config.gost_config_path.read_bytes() == b"working-auth\n"


@pytest.mark.asyncio
async def test_reload_failure_rolls_back_last_working_auth(tmp_path: Path) -> None:
    node_id = uuid.uuid4()
    config = settings(tmp_path, node_id)
    config.gost_config_path.write_bytes(b"working-auth\n")
    body, headers = snapshot_body(node_id)
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers, json=body)

    async def failing_first_reload(_command: tuple[str, ...], _timeout: float) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("reload failed")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    agent = NodeSyncAgent(config, client=client, command_runner=failing_first_reload)
    with pytest.raises(RuntimeError, match="reload failed"):
        await agent.sync_once()
    await client.aclose()
    assert config.gost_config_path.read_bytes() == b"working-auth\n"
    assert calls == 2


@pytest.mark.asyncio
async def test_expired_lease_fail_closes_but_keeps_canary(tmp_path: Path) -> None:
    node_id = uuid.uuid4()
    config = settings(tmp_path, node_id)
    config.gost_config_path.write_text("old_user old_password\n")
    files = AtomicFiles(
        config.gost_config_path,
        config.gost_config_staging_path,
        config.node_sync_state_path,
    )
    files.save_state(
        AgentState(
            revision="a" * 64,
            snapshot_valid_until=datetime(2026, 8, 7, 9, 59, tzinfo=UTC),
            ack_pending=False,
            failed_closed=False,
        )
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    agent = NodeSyncAgent(
        config,
        client=client,
        command_runner=successful_command,
        clock=lambda: datetime(2026, 8, 7, 10, 0, tzinfo=UTC),
    )
    await agent._fail_closed_if_expired()
    await client.aclose()
    content = config.gost_config_path.read_text()
    assert "old_user" not in content
    assert "canary_node_1 " + "C" * 32 in content
    assert files.load_state().failed_closed is True


def test_auth_files_are_group_readable_but_agent_state_is_private(tmp_path: Path) -> None:
    files = AtomicFiles(
        tmp_path / "auth.txt",
        tmp_path / "auth.staging",
        tmp_path / "state.json",
    )

    files.replace_auth(b"user password\n")
    files.replace_auth(b"next password\n")
    files.save_state(AgentState())

    assert files.active_path.stat().st_mode & 0o777 == 0o640
    assert files.backup_path.stat().st_mode & 0o777 == 0o640
    assert files.state_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_lost_ack_response_is_retried_before_conditional_get(tmp_path: Path) -> None:
    node_id = uuid.uuid4()
    config = settings(tmp_path, node_id)
    body, headers = snapshot_body(node_id)
    ack_attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal ack_attempts
        if request.method == "GET" and "if-none-match" not in request.headers:
            return httpx.Response(200, headers=headers, json=body)
        if request.method == "POST":
            ack_attempts += 1
            if ack_attempts <= 2:
                raise httpx.ConnectError("lost response", request=request)
            return httpx.Response(
                200,
                json={
                    "processed": True,
                    "node_id": str(node_id),
                    "revision": body["revision"],
                    "applied_at": "2026-08-07T10:00:01.000Z",
                },
            )
        return httpx.Response(304, headers=headers)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    agent = NodeSyncAgent(config, client=client, command_runner=successful_command)
    with pytest.raises(httpx.ConnectError):
        await agent.sync_once()
    pending = AtomicFiles(
        config.gost_config_path,
        config.gost_config_staging_path,
        config.node_sync_state_path,
    ).load_state()
    assert pending.ack_pending is True

    await agent.sync_once()
    await client.aclose()
    final = AtomicFiles(
        config.gost_config_path,
        config.gost_config_staging_path,
        config.node_sync_state_path,
    ).load_state()
    assert ack_attempts == 3
    assert final.ack_pending is False


def _format(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
