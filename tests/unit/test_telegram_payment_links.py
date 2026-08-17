from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from vpn_service.config import Settings
from vpn_service.security.telegram_payment_links import TelegramPaymentLinkSigner


def test_telegram_payment_link_is_signed_and_expires(
    settings_factory: Callable[..., Settings],
) -> None:
    now = datetime(2026, 8, 17, 8, 0, tzinfo=UTC)
    signer = TelegramPaymentLinkSigner(settings_factory())
    token = signer.issue(telegram_id=123456789, tariff_code="flow_1m", now=now)

    claims = signer.verify(token, now=now + timedelta(days=1))
    assert claims is not None
    assert claims.telegram_id == 123456789
    assert claims.tariff_code == "flow_1m"
    assert signer.verify(token + "x", now=now) is None
    assert signer.verify(token, now=now + timedelta(days=8)) is None
