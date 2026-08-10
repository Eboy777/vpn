from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def generate_discovery_key_pair() -> tuple[str, str]:
    private_value = secrets.randbelow(_P256_ORDER - 1) + 1
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_point = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    return _b64(private_value.to_bytes(32, "big")), _b64(public_point)


def sign_discovery_document(payload: dict[str, Any], private_key_b64: str) -> str:
    private_value = int.from_bytes(_decode(private_key_b64, expected=32), "big")
    if not 1 <= private_value < _P256_ORDER:
        raise ValueError("discovery private key is outside the P-256 scalar range")
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())
    der = private_key.sign(_canonical(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _decode(value: str, *, expected: int) -> bytes:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("discovery key must be base64url") from exc
    if len(decoded) != expected:
        raise ValueError(f"discovery key must decode to {expected} bytes")
    return decoded


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
