from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000


def hash_admin_password(
    password: str,
    *,
    salt: bytes | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> str:
    _validate_password(password)
    if iterations < 100_000 or iterations > 9_999_999:
        raise ValueError("admin password iterations are outside the supported range")
    resolved_salt = salt or secrets.token_bytes(16)
    if len(resolved_salt) != 16:
        raise ValueError("admin password salt must contain 16 bytes")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        resolved_salt,
        iterations,
        dklen=32,
    )
    return "$".join(
        (
            ALGORITHM,
            str(iterations),
            _encode(resolved_salt),
            _encode(digest),
        )
    )


def verify_admin_password(password: str, encoded: str) -> bool:
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if algorithm != ALGORITHM:
            return False
        iterations = int(raw_iterations)
        salt = _decode(raw_salt)
        expected = _decode(raw_digest)
        if len(salt) != 16 or len(expected) != 32:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )
    except (UnicodeError, ValueError):
        return False
    return hmac.compare_digest(candidate, expected)


def _validate_password(password: str) -> None:
    if len(password) < 16:
        raise ValueError("admin password must contain at least 16 characters")
    if len(password.encode("utf-8")) > 1024:
        raise ValueError("admin password is too long")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
