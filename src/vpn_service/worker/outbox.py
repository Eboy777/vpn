from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.enums import OutboxStatus
from vpn_service.persistence.models import OutboxEvent

logger = logging.getLogger(__name__)
OutboxHandler = Callable[[dict[str, Any]], Awaitable[None]]


class OutboxWorker:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
        handlers: dict[str, OutboxHandler] | None = None,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._handlers = handlers or {}

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            processed = await self.process_one()
            if not processed:
                try:
                    await asyncio.wait_for(
                        stop.wait(), timeout=self._settings.worker_poll_interval_seconds
                    )
                except TimeoutError:
                    pass

    async def process_one(self) -> bool:
        async with self._sessions() as session, session.begin():
            event = await session.scalar(
                select(OutboxEvent)
                .where(
                    OutboxEvent.status == OutboxStatus.PENDING.value,
                    OutboxEvent.available_at <= datetime.now(UTC),
                )
                .order_by(OutboxEvent.created_at, OutboxEvent.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if event is None:
                return False

            handler = self._handlers.get(event.event_type)
            if handler is None:
                event.attempts += 1
                event.status = OutboxStatus.FAILED.value
                event.last_error_code = "UNSUPPORTED_EVENT_TYPE"
                logger.error(
                    "unsupported_outbox_event",
                    extra={
                        "event_data": {
                            "event": "outbox_failed",
                            "outbox_event_id": str(event.id),
                            "event_type": event.event_type,
                            "error_code": event.last_error_code,
                        }
                    },
                )
                return True

            event.status = OutboxStatus.PROCESSING.value
            event.attempts += 1
            try:
                await handler(event.payload_json)
            except Exception:
                if event.attempts >= self._settings.outbox_max_attempts:
                    event.status = OutboxStatus.FAILED.value
                else:
                    event.status = OutboxStatus.PENDING.value
                    delay = min(
                        self._settings.outbox_retry_max_seconds,
                        self._settings.outbox_retry_base_seconds * (2 ** (event.attempts - 1)),
                    )
                    event.available_at = datetime.now(UTC) + timedelta(seconds=delay)
                event.last_error_code = "HANDLER_FAILED"
                logger.exception(
                    "outbox_handler_failed",
                    extra={
                        "event_data": {
                            "event": "outbox_retry",
                            "outbox_event_id": str(event.id),
                            "event_type": event.event_type,
                            "attempt": event.attempts,
                            "error_code": event.last_error_code,
                        }
                    },
                )
            else:
                event.status = OutboxStatus.SUCCEEDED.value
                event.processed_at = datetime.now(UTC)
                event.last_error_code = None
            return True
