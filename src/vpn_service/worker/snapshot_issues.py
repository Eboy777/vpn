from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.persistence.models import NodeSnapshotIssue


class SnapshotIssuePruner:
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
                    timeout=self._settings.rate_limit_cleanup_interval_seconds,
                )
            except TimeoutError:
                pass

    async def prune_once(self) -> int:
        cutoff = self._clock().astimezone(UTC) - timedelta(
            seconds=self._settings.node_snapshot_issue_retention_seconds
        )
        async with self._sessions.begin() as session:
            result = await session.execute(
                delete(NodeSnapshotIssue).where(NodeSnapshotIssue.snapshot_valid_until < cutoff)
            )
            return int(result.rowcount)  # type: ignore[attr-defined]
