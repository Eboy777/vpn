from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.persistence.models import (
    CanaryRun,
    ExtensionLifecycleEvent,
    NodeCheckEvent,
    NodeTelemetryReport,
    UserActivityEvent,
    VpnSession,
)


class AnalyticsRetentionWorker:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.prune_once()
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._settings.analytics_cleanup_interval_seconds,
                )
            except TimeoutError:
                pass

    async def prune_once(self) -> int:
        now = self._clock().astimezone(UTC)
        raw_cutoff = now - timedelta(days=self._settings.analytics_raw_event_retention_days)
        report_cutoff = now - timedelta(days=7)
        statements = (
            delete(ExtensionLifecycleEvent).where(ExtensionLifecycleEvent.received_at < raw_cutoff),
            delete(UserActivityEvent).where(UserActivityEvent.received_at < raw_cutoff),
            delete(VpnSession).where(VpnSession.last_seen_at < raw_cutoff),
            delete(NodeCheckEvent).where(NodeCheckEvent.created_at < raw_cutoff),
            delete(CanaryRun).where(CanaryRun.received_at < raw_cutoff),
            delete(NodeTelemetryReport).where(NodeTelemetryReport.received_at < report_cutoff),
        )
        deleted = 0
        async with self._sessions.begin() as session:
            for statement in statements:
                result = await session.execute(statement)
                deleted += int(result.rowcount)  # type: ignore[attr-defined]
        return deleted
