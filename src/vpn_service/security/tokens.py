from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from vpn_service.config import Settings


@dataclass(frozen=True, slots=True)
class IssuedToken:
    raw: str
    key_id: str
    digest: bytes


class TokenHasher:
    """Issue opaque tokens and derive domain-separated, versioned HMAC hashes."""

    def __init__(self, settings: Settings) -> None:
        self._keys = {
            domain: {
                key_id: _decode_key(secret.get_secret_value())
                for key_id, secret in versions.items()
            }
            for domain, versions in settings.token_hash_keyring_json.items()
        }
        self._active = dict(settings.token_hash_active_key_ids_json)

    def issue(self, domain: str) -> IssuedToken:
        raw = secrets.token_urlsafe(32)
        if len(raw) != 43:  # pragma: no cover - guaranteed for 32 input bytes
            raise RuntimeError("unexpected token length")
        key_id = self._active[domain]
        return IssuedToken(raw=raw, key_id=key_id, digest=self.digest(domain, key_id, raw))

    def digest(self, domain: str, key_id: str, raw: str) -> bytes:
        key = self._keys[domain][key_id]
        message = f"vpn-control:{domain}:v1:{raw}".encode()
        return hmac.digest(key, message, hashlib.sha256)

    def candidates(self, domain: str, raw: str) -> list[tuple[str, bytes]]:
        return [(key_id, self.digest(domain, key_id, raw)) for key_id in sorted(self._keys[domain])]

    def opaque_subject(self, scope: str, value: str) -> bytes:
        key_id = self._active["pairing_session"]
        key = self._keys["pairing_session"][key_id]
        return hmac.digest(key, f"rate-limit:{scope}:{value}".encode(), hashlib.sha256)


def _decode_key(raw: str) -> bytes:
    return base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
