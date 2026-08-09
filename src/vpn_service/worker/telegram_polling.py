from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol

from pydantic import ValidationError

from vpn_service.application.telegram_bot import TelegramBotService
from vpn_service.external.telegram import TelegramBotClient, TelegramDeliveryError
from vpn_service.http.schemas import TelegramUpdateRequest

logger = logging.getLogger(__name__)


class TelegramUpdateProcessor(Protocol):
    async def process_update(self, update: TelegramUpdateRequest) -> str: ...


class TelegramPollingWorker:
    """Development transport; production remains webhook-only by Settings validation."""

    def __init__(
        self,
        service: TelegramBotService | TelegramUpdateProcessor,
        client: TelegramBotClient,
    ) -> None:
        self._service = service
        self._client = client

    async def run_forever(self, stop: asyncio.Event) -> None:
        offset: int | None = None
        prepared = False
        while not stop.is_set():
            try:
                if not prepared:
                    await self._client.prepare_polling()
                    prepared = True
                updates = await self._client.get_updates(offset=offset)
                offset = await self._process_batch(updates, offset=offset)
            except TelegramDeliveryError:
                logger.warning("telegram_polling_delivery_error")
                await _wait_or_stop(stop, 5)
            except Exception:
                logger.exception("telegram_polling_processing_error")
                await _wait_or_stop(stop, 2)

    async def _process_batch(
        self,
        updates: list[dict[str, Any]],
        *,
        offset: int | None,
    ) -> int | None:
        next_offset = offset
        for raw_update in updates:
            update_id = raw_update.get("update_id")
            try:
                update = TelegramUpdateRequest.model_validate(raw_update)
            except ValidationError:
                logger.warning(
                    "telegram_polling_unsupported_update",
                    extra={
                        "event_data": {
                            "event": "telegram_update_skipped",
                            "update_id": update_id if isinstance(update_id, int) else None,
                        }
                    },
                )
                if isinstance(update_id, int) and update_id >= 0:
                    next_offset = max(next_offset or 0, update_id + 1)
                continue
            await self._service.process_update(update)
            next_offset = max(next_offset or 0, update.update_id + 1)
        return next_offset


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        pass
