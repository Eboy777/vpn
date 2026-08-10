from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from vpn_service.app import create_app
from vpn_service.config import Settings

EXTENSION_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"


async def _database_probe() -> bool:
    return True


@pytest.fixture
async def cors_client(
    settings_factory: Callable[..., Settings],
) -> AsyncIterator[httpx.AsyncClient]:
    settings = settings_factory(allowed_extension_origins_json=[EXTENSION_ORIGIN])
    app = create_app(settings, database_probe=_database_probe)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "method", "headers"),
    [
        ("/api/discovery/control-ingresses", "GET", "x-request-id"),
        ("/api/pairing/init", "POST", "content-type,x-request-id"),
        ("/api/pairing/status", "GET", "authorization,x-request-id"),
        ("/api/status", "GET", "authorization,x-request-id"),
        ("/api/nodes", "GET", "authorization,x-request-id"),
        ("/api/nodes/select", "POST", "authorization,content-type,x-request-id"),
        (
            "/api/payments/create",
            "POST",
            "authorization,content-type,idempotency-key,x-request-id",
        ),
    ],
)
async def test_extension_routes_accept_exact_preflight(
    cors_client: httpx.AsyncClient,
    path: str,
    method: str,
    headers: str,
) -> None:
    response = await cors_client.options(
        path,
        headers={
            "Origin": EXTENSION_ORIGIN,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": headers,
        },
    )

    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == EXTENSION_ORIGIN
    assert "Authorization" in response.headers["access-control-allow-headers"]


@pytest.mark.asyncio
async def test_extension_cors_rejects_wrong_method_and_origin(
    cors_client: httpx.AsyncClient,
) -> None:
    wrong_method = await cors_client.options(
        "/api/status",
        headers={
            "Origin": EXTENSION_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    wrong_origin = await cors_client.options(
        "/api/status",
        headers={
            "Origin": "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )

    assert wrong_method.status_code == 400
    assert wrong_method.json()["error"]["code"] == "CORS_PREFLIGHT_INVALID"
    assert wrong_origin.status_code == 403
    assert wrong_origin.json()["error"]["code"] == "CORS_ORIGIN_DENIED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("GET", "/api/discovery/control-ingresses", {}),
        ("GET", "/api/status", {"headers": {"Authorization": "Bearer " + "a" * 43}}),
        ("GET", "/api/nodes", {"headers": {"Authorization": "Bearer " + "a" * 43}}),
        (
            "POST",
            "/api/nodes/select",
            {
                "headers": {"Authorization": "Bearer " + "a" * 43},
                "json": {"node_id": None},
            },
        ),
    ],
)
async def test_extension_routes_expose_cors_on_error_responses(
    cors_client: httpx.AsyncClient,
    method: str,
    path: str,
    kwargs: dict[str, object],
) -> None:
    headers = dict(kwargs.pop("headers", {}))
    headers["Origin"] = EXTENSION_ORIGIN
    response = await cors_client.request(method, path, headers=headers, **kwargs)

    assert response.status_code == 503
    assert response.headers["access-control-allow-origin"] == EXTENSION_ORIGIN
    assert "X-Request-ID" in response.headers["access-control-expose-headers"]
