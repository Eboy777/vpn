from __future__ import annotations

import json
import uuid

import httpx
import pytest

from vpn_service.node_observer.config import NodeObserverSettings
from vpn_service.node_observer.service import (
    LimiterRequest,
    NodeObserver,
    ObserverEvent,
    ObserverPayload,
    ObserverStats,
)


@pytest.mark.asyncio
async def test_node_observer_reports_only_authenticated_gost_users_and_aggregates_deltas() -> None:
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"processed": True})

    settings = NodeObserverSettings(
        control_api_base_url="https://api-a.example.test",
        control_api_fallback_urls_json=["https://api-b.example.test"],
        node_id=uuid.uuid4(),
        node_credentials_token="N" * 43,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    observer = NodeObserver(settings, client=client, service_probe=lambda _: _false())
    try:
        accepted = await observer.observe(
            ObserverPayload(
                events=[
                    ObserverEvent(
                        kind="handler",
                        type="stats",
                        client="u_abcdefghijklmnopqrstuvwxyz",
                        stats=ObserverStats(
                            totalConns=2,
                            currentConns=1,
                            inputBytes=100,
                            outputBytes=200,
                            totalErrs=3,
                        ),
                    ),
                    ObserverEvent(
                        kind="handler",
                        type="stats",
                        client="untrusted-client",
                        stats=ObserverStats(totalConns=99),
                    ),
                ]
            )
        )
        assert await observer.flush() is True
    finally:
        await client.aclose()

    assert accepted == 1
    assert len(requests) == 1
    assert requests[0]["clients"] == [
        {
            "proxy_username": "u_abcdefghijklmnopqrstuvwxyz",
            "total_connections": 2,
            "current_connections": 1,
            "input_bytes": 100,
            "output_bytes": 200,
            "total_errors": 3,
            "connection_seconds": 15,
        }
    ]


@pytest.mark.asyncio
async def test_node_observer_retries_the_same_report_after_an_uncertain_failure() -> None:
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(503 if len(requests) == 1 else 200, json={"ok": True})

    settings = NodeObserverSettings(
        control_api_base_url="https://api-a.example.test",
        node_id=uuid.uuid4(),
        node_credentials_token="N" * 43,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    observer = NodeObserver(settings, client=client, service_probe=lambda _: _false())
    event = ObserverEvent(
        kind="handler",
        type="stats",
        client="u_abcdefghijklmnopqrstuvwxyz",
        stats=ObserverStats(totalConns=1, inputBytes=10),
    )
    try:
        await observer.observe(ObserverPayload(events=[event]))
        assert await observer.flush() is False
        await observer.observe(ObserverPayload(events=[event]))
        assert await observer.flush() is True
        assert await observer.flush() is True
    finally:
        await client.aclose()

    assert requests[0]["report_id"] == requests[1]["report_id"]
    assert requests[0]["clients"] == requests[1]["clients"]
    assert requests[2]["report_id"] != requests[1]["report_id"]
    assert requests[2]["clients"][0]["input_bytes"] == 10  # type: ignore[index]


async def _false() -> bool:
    return False


def test_account_limiter_uses_authenticated_client_not_source_ip(tmp_path) -> None:
    limits = tmp_path / "account-limits.json"
    limits.write_text(json.dumps({"u_abcdefghijklmnopqrstuvwxyz": 5_000_000}))
    settings = NodeObserverSettings(
        control_api_base_url="https://api-a.example.test",
        node_id=uuid.uuid4(),
        node_credentials_token="N" * 43,
        gost_account_limits_path=limits,
    )
    observer = NodeObserver(settings, service_probe=lambda _: _false())

    first = observer.account_limit(LimiterRequest(
        scope="client",
        client="u_abcdefghijklmnopqrstuvwxyz",
    ))
    paid = observer.account_limit(LimiterRequest(
        scope="client",
        client="u_zyxwvutsrqponmlkjihgfedcba",
    ))
    connection_scope = observer.account_limit(LimiterRequest(
        scope="conn",
        client="u_abcdefghijklmnopqrstuvwxyz",
    ))

    assert first == {"in": 5_000_000, "out": 5_000_000}
    assert paid == {"in": 0, "out": 0}
    assert connection_scope == {"in": 0, "out": 0}
