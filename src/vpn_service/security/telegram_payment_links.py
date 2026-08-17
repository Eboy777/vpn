from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from vpn_service.config import Settings

_TARIFF_CODE = re.compile(r"^[a-z0-9_]{3,32}$")
_MAX_LINK_AGE = timedelta(days=7)


@dataclass(frozen=True, slots=True)
class TelegramPaymentLink:
    telegram_id: int
    tariff_code: str
    expires_at: datetime


class TelegramPaymentLinkSigner:
    def __init__(self, settings: Settings) -> None:
        domain_keys = settings.token_hash_keyring_json["pairing_session"]
        self._keys = {
            key_id: _decode(secret.get_secret_value()) for key_id, secret in domain_keys.items()
        }
        self._active_key_id = settings.token_hash_active_key_ids_json["pairing_session"]

    def issue(self, *, telegram_id: int, tariff_code: str, now: datetime) -> str:
        if telegram_id <= 0 or _TARIFF_CODE.fullmatch(tariff_code) is None:
            raise ValueError("invalid Telegram payment link subject")
        expires_at = now.astimezone(UTC) + _MAX_LINK_AGE
        payload = (
            f"v1.{self._active_key_id}.{telegram_id}.{tariff_code}.{int(expires_at.timestamp())}"
        )
        signature = hmac.digest(
            self._keys[self._active_key_id],
            b"vpn-control:telegram-payment-link:v1:" + payload.encode(),
            hashlib.sha256,
        )
        return payload + "." + _encode(signature)

    def verify(self, token: str, *, now: datetime) -> TelegramPaymentLink | None:
        parts = token.split(".")
        if len(parts) != 6 or parts[0] != "v1":
            return None
        _, key_id, telegram_raw, tariff_code, expires_raw, signature_raw = parts
        key = self._keys.get(key_id)
        if key is None or _TARIFF_CODE.fullmatch(tariff_code) is None:
            return None
        try:
            telegram_id = int(telegram_raw)
            expires_at = datetime.fromtimestamp(int(expires_raw), tz=UTC)
            signature = _decode(signature_raw)
        except (ValueError, OverflowError):
            return None
        if telegram_id <= 0 or expires_at <= now.astimezone(UTC):
            return None
        payload = ".".join(parts[:5])
        expected = hmac.digest(
            key,
            b"vpn-control:telegram-payment-link:v1:" + payload.encode(),
            hashlib.sha256,
        )
        if not hmac.compare_digest(signature, expected):
            return None
        return TelegramPaymentLink(telegram_id, tariff_code, expires_at)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
