from __future__ import annotations

import base64
import json
import secrets
import string
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vpn_service.config import Settings


@dataclass(frozen=True, slots=True)
class ProxyCredentials:
    username: str
    password: str
    password_ciphertext: bytes
    key_id: str


class ProxyCredentialsCipher:
    def __init__(self, settings: Settings) -> None:
        self._keys = {
            key_id: _decode_key(secret.get_secret_value())
            for key_id, secret in settings.proxy_credentials_keyring_json.items()
        }
        self._active_key_id = settings.proxy_credentials_active_key_id

    def generate(self, user_id: uuid.UUID) -> ProxyCredentials:
        alphabet = string.ascii_lowercase + string.digits
        username = "u_" + "".join(secrets.choice(alphabet) for _ in range(26))
        password = secrets.token_urlsafe(24)
        return ProxyCredentials(
            username=username,
            password=password,
            password_ciphertext=self.encrypt(user_id, password),
            key_id=self._active_key_id,
        )

    def encrypt(self, user_id: uuid.UUID, password: str) -> bytes:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._keys[self._active_key_id]).encrypt(
            nonce,
            password.encode("ascii"),
            user_id.bytes,
        )
        envelope = {
            "v": 1,
            "kid": self._active_key_id,
            "nonce": _encode(nonce),
            "ciphertext": _encode(ciphertext),
        }
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("ascii")

    def decrypt(self, user_id: uuid.UUID, envelope_bytes: bytes) -> str:
        envelope = json.loads(envelope_bytes)
        if set(envelope) != {"v", "kid", "nonce", "ciphertext"} or envelope["v"] != 1:
            raise ValueError("invalid proxy credentials envelope")
        key_id = envelope["kid"]
        if not isinstance(key_id, str) or key_id not in self._keys:
            raise ValueError("unknown proxy credentials key")
        plaintext = AESGCM(self._keys[key_id]).decrypt(
            _decode(envelope["nonce"]),
            _decode(envelope["ciphertext"]),
            user_id.bytes,
        )
        return plaintext.decode("ascii")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _decode_key(raw: str) -> bytes:
    key = _decode(raw)
    if len(key) != 32:  # Settings has already validated this.
        raise ValueError("proxy credentials key must contain 32 bytes")
    return key
