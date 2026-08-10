from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.device_auth import AuthenticatedDevice
from vpn_service.config import Settings
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.schemas import DeviceTelemetryRequest, ExtensionLifecycleRequest
from vpn_service.persistence.models import (
    ExtensionInstallation,
    ExtensionLifecycleEvent,
    User,
    UserActivityEvent,
    VpnSession,
)
from vpn_service.persistence.rate_limits import consume_rate_limit
from vpn_service.security.tokens import TokenHasher


class TelemetryService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._tokens = TokenHasher(settings)

    async def record_lifecycle(
        self,
        payload: ExtensionLifecycleRequest,
        *,
        source_ip: str,
    ) -> bool:
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            await self._enforce_rate_limit(
                session,
                scope="telemetry-install-minute",
                subject_value=source_ip,
                limit=self._settings.telemetry_install_rate_per_minute,
                now=now,
            )
            inserted = (
                await session.execute(
                    insert(ExtensionLifecycleEvent)
                    .values(
                        event_id=payload.event_id,
                        installation_id=payload.installation_id,
                        event_type=payload.event_type,
                        extension_version=payload.extension_version,
                        browser_name=payload.browser_name,
                        browser_version=payload.browser_version,
                        platform=payload.platform,
                        source_ip=source_ip,
                        received_at=now,
                    )
                    .on_conflict_do_nothing(index_elements=[ExtensionLifecycleEvent.event_id])
                    .returning(ExtensionLifecycleEvent.event_id)
                )
            ).scalar_one_or_none()
            if inserted is None:
                return False

            launch_increment = 1 if payload.event_type in {"installed", "launched"} else 0
            await session.execute(
                insert(ExtensionInstallation)
                .values(
                    installation_id=payload.installation_id,
                    extension_version=payload.extension_version,
                    browser_name=payload.browser_name,
                    browser_version=payload.browser_version,
                    platform=payload.platform,
                    launch_count=launch_increment,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                .on_conflict_do_update(
                    index_elements=[ExtensionInstallation.installation_id],
                    set_={
                        "extension_version": payload.extension_version,
                        "browser_name": payload.browser_name,
                        "browser_version": payload.browser_version,
                        "platform": payload.platform,
                        "last_seen_at": now,
                        "launch_count": (ExtensionInstallation.launch_count + launch_increment),
                    },
                )
            )
            return True

    async def record_device_event(
        self,
        device: AuthenticatedDevice,
        payload: DeviceTelemetryRequest,
        *,
        source_ip: str,
    ) -> bool:
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            await self._enforce_rate_limit(
                session,
                scope="telemetry-device-minute",
                subject_value=str(device.device_row_id),
                limit=self._settings.telemetry_device_rate_per_minute,
                now=now,
            )
            user = await session.get(User, device.user_id)
            if user is None:
                raise ApplicationError(401, "INVALID_DEVICE_TOKEN", "Device token is invalid")
            inserted = (
                await session.execute(
                    insert(UserActivityEvent)
                    .values(
                        event_id=payload.event_id,
                        user_id=user.id,
                        device_id=device.device_row_id,
                        node_id=user.assigned_node_id,
                        session_id=payload.session_id,
                        event_type=payload.event_type,
                        error_code=payload.error_code,
                        extension_version=payload.extension_version,
                        browser_name=payload.browser_name,
                        browser_version=payload.browser_version,
                        platform=payload.platform,
                        duration_ms=payload.duration_ms,
                        source_ip=source_ip,
                        received_at=now,
                    )
                    .on_conflict_do_nothing(index_elements=[UserActivityEvent.event_id])
                    .returning(UserActivityEvent.event_id)
                )
            ).scalar_one_or_none()
            if inserted is None:
                return False

            if payload.event_type == "tariff_viewed":
                return True

            assert payload.session_id is not None

            vpn_session = await session.get(VpnSession, payload.session_id)
            if vpn_session is not None and (
                vpn_session.user_id != user.id or vpn_session.device_id != device.device_row_id
            ):
                raise ApplicationError(409, "SESSION_ID_CONFLICT", "Session ID is already used")
            if vpn_session is None:
                vpn_session = VpnSession(
                    id=payload.session_id,
                    user_id=user.id,
                    device_id=device.device_row_id,
                    node_id=user.assigned_node_id,
                    source_ip=source_ip,
                    extension_version=payload.extension_version,
                    browser_name=payload.browser_name,
                    browser_version=payload.browser_version,
                    platform=payload.platform,
                    status="active",
                    connection_errors=0,
                    connection_duration_ms=payload.duration_ms,
                    failover_count=0,
                    reconnect_count=0,
                    started_at=now,
                    last_seen_at=now,
                )
                session.add(vpn_session)
            else:
                vpn_session.node_id = user.assigned_node_id
                vpn_session.source_ip = source_ip
                vpn_session.extension_version = payload.extension_version
                vpn_session.browser_name = payload.browser_name
                vpn_session.browser_version = payload.browser_version
                vpn_session.platform = payload.platform
                vpn_session.last_seen_at = now

            if payload.event_type == "connection_error":
                vpn_session.connection_errors += 1
                vpn_session.status = "error"
            elif payload.event_type == "node_failover":
                vpn_session.failover_count += 1
                vpn_session.status = "active"
            elif payload.event_type == "reconnect":
                vpn_session.reconnect_count += 1
                vpn_session.status = "active"
            elif payload.event_type == "vpn_stopped":
                vpn_session.status = "ended"
                vpn_session.ended_at = now
            else:
                vpn_session.status = "active"
                vpn_session.ended_at = None
            if payload.event_type == "vpn_started" and payload.duration_ms is not None:
                vpn_session.connection_duration_ms = payload.duration_ms
            return True

    async def _enforce_rate_limit(
        self,
        session: AsyncSession,
        *,
        scope: str,
        subject_value: str,
        limit: int,
        now: datetime,
    ) -> None:
        decision = await consume_rate_limit(
            session,
            scope=scope,
            subject_hash=self._tokens.opaque_subject(scope, subject_value),
            limit=limit,
            window_seconds=60,
            now=now,
        )
        if not decision.allowed:
            raise ApplicationError(
                429,
                "RATE_LIMITED",
                "Rate limit exceeded",
                headers={
                    "Retry-After": str(decision.retry_after),
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": str(decision.remaining),
                },
            )


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
