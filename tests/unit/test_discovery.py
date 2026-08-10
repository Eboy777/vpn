from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from vpn_service.app import create_app
from vpn_service.application.discovery import normalize_https_origin
from vpn_service.config import Settings
from vpn_service.security.discovery_signing import (
    generate_discovery_key_pair,
    sign_discovery_document,
)


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_discovery_document_uses_browser_compatible_p256_signature() -> None:
    private_key, public_key = generate_discovery_key_pair()
    now = datetime.now(UTC)
    payload = {
        "version": "a" * 64,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "control_urls": ["https://api-a.example", "https://api-b.example"],
        "key_id": "v1",
    }
    signature = _decode(sign_discovery_document(payload, private_key))
    point = _decode(public_key)
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(point[1:33], "big"),
        int.from_bytes(point[33:], "big"),
        ec.SECP256R1(),
    )
    der_signature = encode_dss_signature(
        int.from_bytes(signature[:32], "big"),
        int.from_bytes(signature[32:], "big"),
    )

    numbers.public_key().verify(
        der_signature,
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    assert len(signature) == 64
    assert len(point) == 65


@pytest.mark.parametrize(
    "value",
    [
        "http://api.example",
        "https://api.example/path",
        "https://user:password@api.example",
        "https://api.example?query=1",
    ],
)
def test_discovery_rejects_non_origin_addresses(value: str) -> None:
    with pytest.raises(ValueError, match="plain HTTPS origin"):
        normalize_https_origin(value)


@pytest.mark.asyncio
async def test_discovery_endpoint_is_public_but_requires_configured_service(
    settings_factory,
) -> None:
    settings: Settings = settings_factory()
    app = create_app(settings, database_probe=lambda: None)  # type: ignore[arg-type]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/discovery/control-ingresses")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"
