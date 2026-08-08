from __future__ import annotations

from starlette.requests import Request

from vpn_service.http.client_ip import client_ip


def _request(peer: str, forwarded_for: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
            "client": (peer, 12345),
            "server": ("backend", 8000),
            "scheme": "http",
            "query_string": b"",
        }
    )


def test_ignores_forwarded_for_from_untrusted_peer() -> None:
    request = _request("198.51.100.8", "203.0.113.20")

    assert client_ip(request, ["10.77.0.2/32", "10.77.0.3/32"]) == "198.51.100.8"


def test_accepts_client_address_from_trusted_proxy() -> None:
    request = _request("10.77.0.2", "203.0.113.20")

    assert client_ip(request, ["10.77.0.2/32", "10.77.0.3/32"]) == "203.0.113.20"


def test_rejects_forwarded_chain_in_direct_ingress_architecture() -> None:
    request = _request("10.77.0.3", "203.0.113.20, 10.77.0.2")

    assert client_ip(request, ["10.77.0.2/32", "10.77.0.3/32"]) == "10.77.0.3"


def test_rejects_malformed_forwarded_chain() -> None:
    request = _request("10.77.0.2", "203.0.113.20, invalid")

    assert client_ip(request, ["10.77.0.2/32", "10.77.0.3/32"]) == "10.77.0.2"
