from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.enums import DeviceStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.persistence.models import Device
from vpn_service.security.tokens import TokenHasher


@dataclass(frozen=True, slots=True)
class AuthenticatedDevice:
    device_row_id: uuid.UUID
    device_id: uuid.UUID
    user_id: uuid.UUID


class DeviceAuthenticator:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._tokens = TokenHasher(settings)

    async def authenticate(self, raw_token: str) -> AuthenticatedDevice:
        candidates = self._tokens.candidates("device", raw_token)
        predicate = or_(
            *(
                and_(
                    Device.device_token_key_id == key_id,
                    Device.device_token_hash == digest,
                )
                for key_id, digest in candidates
            )
        )
        async with self._sessions.begin() as session:
            device = (
                await session.execute(select(Device).where(predicate).with_for_update())
            ).scalar_one_or_none()
            if device is None:
                raise _invalid_device_token()
            if device.status == DeviceStatus.REVOKED.value:
                raise ApplicationError(
                    401,
                    "DEVICE_REVOKED",
                    "Device is revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if device.status != DeviceStatus.ACTIVE.value or device.user_id is None:
                raise _invalid_device_token()

            device.pairing_session_token_hash = None
            device.pairing_session_token_key_id = None
            device.pairing_expires_at = None
            now = await session.scalar(select(func.now()))
            assert now is not None
            normalized_now = now.astimezone(UTC)
            if device.last_seen_at is None or device.last_seen_at <= normalized_now - timedelta(
                seconds=self._settings.device_last_seen_write_interval_seconds
            ):
                device.last_seen_at = normalized_now
            return AuthenticatedDevice(
                device_row_id=device.id,
                device_id=device.device_id,
                user_id=device.user_id,
            )


def _invalid_device_token() -> ApplicationError:
    return ApplicationError(
        401,
        "INVALID_DEVICE_TOKEN",
        "Device token is invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )
