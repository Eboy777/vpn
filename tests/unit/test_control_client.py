from __future__ import annotations

import uuid

import httpx
import pytest

from vpn_service.api_proxy_check import check_ingresses
from vpn_service.external.control_client import (
    ControlClientPolicy,
    ControlPlaneClient,
    ControlPlaneUnavailable,
    validate_control_urls,
)

URLS = ("https://api-a.vpn.example", "https://api-b.vpn.example")


@pytest.mark.asyncio
async def test_network_error_fails_over_to_second_ingress() -> None:
    seen: list[str] = []
    request_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        request_ids.append(request.headers["X-Request-ID"])
        if request.url.host == "api-a.vpn.example":
            raise httpx.ConnectError("primary unavailable", request=request)
        return httpx.Response(200, json={"status": "ok"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = ControlPlaneClient(URLS, client=http_client)
        response = await client.request("GET", "/api/status")

    assert response.status_code == 200
    assert seen == ["api-a.vpn.example", "api-b.vpn.example"]
    assert len(set(request_ids)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 502, 503, 504])
async def test_retryable_status_fails_over(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status if request.url.host.startswith("api-a") else 200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await ControlPlaneClient(URLS, client=http_client).request(
            "GET", "/health/ready"
        )

    assert response.status_code == 200
    assert response.request.url.host == "api-b.vpn.example"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 429, 500])
async def test_non_failover_status_is_returned_without_trying_second_ingress(status: int) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(status, headers={"Retry-After": "30"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await ControlPlaneClient(URLS, client=http_client).request("GET", "/api/status")

    assert response.status_code == status
    assert seen == ["api-a.vpn.example"]


@pytest.mark.asyncio
async def test_exhaustion_uses_bounded_backoff() -> None:
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    policy = ControlClientPolicy(
        attempts_per_url=3,
        backoff_base_seconds=0.25,
        backoff_max_seconds=0.4,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = ControlPlaneClient(URLS, client=http_client, policy=policy, sleep=record_sleep)
        with pytest.raises(ControlPlaneUnavailable, match="all control ingress attempts failed"):
            await client.request("GET", "/api/status")

    assert sleeps == [0.25, 0.4]


@pytest.mark.asyncio
async def test_retry_after_pauses_next_request_globally() -> None:
    responses = iter(
        [
            httpx.Response(429, headers={"Retry-After": "30"}),
            httpx.Response(200),
        ]
    )
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: next(responses))
    ) as http_client:
        client = ControlPlaneClient(
            URLS,
            client=http_client,
            sleep=record_sleep,
            clock=lambda: 100.0,
        )
        first = await client.request("GET", "/api/status")
        second = await client.request("GET", "/api/status")

    assert first.status_code == 429
    assert second.status_code == 200
    assert sleeps == [30.0]


@pytest.mark.asyncio
async def test_checker_requires_both_ingresses_to_be_ready() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-Request-ID": str(uuid.uuid5(uuid.NAMESPACE_DNS, request.url.host))},
            json={"status": "ok", "database": "ok"},
        )

    results = await check_ingresses(URLS, transport=httpx.MockTransport(handler))

    assert [result["url"] for result in results] == list(URLS)


@pytest.mark.parametrize(
    "urls",
    [
        ["https://api-a.vpn.example"],
        ["https://api-a.vpn.example", "https://api-a.vpn.example"],
        ["http://api-a.vpn.example", "https://api-b.vpn.example"],
        ["https://api-a.vpn.example:8443", "https://api-b.vpn.example"],
        ["https://user@api-a.vpn.example", "https://api-b.vpn.example"],
        ["https://api-a.vpn.example/path", "https://api-b.vpn.example"],
        ["https://API-A.vpn.example", "https://api-a.vpn.example"],
    ],
)
def test_control_url_validation_rejects_unsafe_values(urls: list[str]) -> None:
    with pytest.raises(ValueError):
        validate_control_urls(urls)


@pytest.mark.asyncio
async def test_non_idempotent_methods_are_not_automatically_retried() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200))
    ) as http_client:
        client = ControlPlaneClient(URLS, client=http_client)
        with pytest.raises(ValueError, match="idempotent"):
            await client.request("POST", "/api/nodes/select")
