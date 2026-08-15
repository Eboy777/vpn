from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vpn_service.application.pairing import PairingService
from vpn_service.config import Settings


@pytest.mark.asyncio
async def test_paid_tariff_controls_device_limit(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    service = PairingService(object(), settings)  # type: ignore[arg-type]
    session = AsyncMock()
    now = datetime(2026, 8, 10, tzinfo=UTC)
    user = SimpleNamespace(
        id=uuid.uuid4(),
        subscription_expires_at=now + timedelta(days=30),
    )

    session.scalar.return_value = "flow_3m"
    assert await service._device_limit(session, user, now) == 4  # noqa: SLF001

    session.scalar.return_value = "space_6m"
    assert await service._device_limit(session, user, now) == 8  # noqa: SLF001


@pytest.mark.asyncio
async def test_trial_keeps_default_device_limit(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    service = PairingService(object(), settings)  # type: ignore[arg-type]
    session = AsyncMock()
    now = datetime(2026, 8, 10, tzinfo=UTC)
    user = SimpleNamespace(id=uuid.uuid4(), subscription_expires_at=None)

    assert await service._device_limit(session, user, now) == 3  # noqa: SLF001
    session.scalar.assert_not_awaited()
