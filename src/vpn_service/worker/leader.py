from __future__ import annotations

from types import TracebackType

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

WORKER_ADVISORY_LOCK_ID = 8_617_331_045_521_327


class WorkerAlreadyRunningError(RuntimeError):
    pass


class WorkerLeader:
    """Owns a session-level PostgreSQL advisory lock on a dedicated connection."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._connection: AsyncConnection | None = None

    async def __aenter__(self) -> WorkerLeader:
        connection = await self._engine.connect()
        acquired = await connection.scalar(
            text("SELECT pg_try_advisory_lock(:lock_id)"),
            {"lock_id": WORKER_ADVISORY_LOCK_ID},
        )
        if not acquired:
            await connection.close()
            raise WorkerAlreadyRunningError("another scheduler worker owns the advisory lock")
        self._connection = connection
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._connection is None:
            return
        try:
            await self._connection.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": WORKER_ADVISORY_LOCK_ID},
            )
        finally:
            await self._connection.close()
            self._connection = None
