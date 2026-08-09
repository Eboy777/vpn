from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.enums import OutboxStatus, UserStatus
from vpn_service.persistence.models import OutboxEvent, User


class SubscriptionReminderWorker:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.enqueue_due()
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._settings.subscription_reminder_poll_seconds,
                )
            except TimeoutError:
                pass

    async def enqueue_due(self) -> int:
        async with self._sessions.begin() as session:
            now = await _transaction_now(session)
            users = (
                await session.scalars(
                    select(User).where(
                        User.status == UserStatus.ACTIVE.value,
                        User.subscription_expires_at > now,
                        User.subscription_expires_at <= now + timedelta(days=3),
                    )
                )
            ).all()
            inserted_count = 0
            for user in users:
                assert user.subscription_expires_at is not None
                remaining = user.subscription_expires_at - now
                days = 1 if remaining <= timedelta(days=1) else 3
                expiry_key = int(user.subscription_expires_at.timestamp())
                inserted = (
                    await session.execute(
                        insert(OutboxEvent)
                        .values(
                            id=uuid.uuid4(),
                            event_type="telegram.call",
                            aggregate_type="telegram_user",
                            aggregate_id=user.id,
                            idempotency_key=(
                                f"telegram:subscription-expiry:{user.id}:{expiry_key}:{days}d"
                            ),
                            payload_json={
                                "method": "sendMessage",
                                "params": {
                                    "chat_id": user.telegram_id,
                                    "text": (
                                        f"Подписка закончится через {days} "
                                        f"{'день' if days == 1 else 'дня'}."
                                    ),
                                    "reply_markup": {
                                        "inline_keyboard": [
                                            [
                                                {
                                                    "text": "⚡ Быстрое продление",
                                                    "callback_data": "menu:tariffs",
                                                }
                                            ]
                                        ]
                                    },
                                },
                            },
                            status=OutboxStatus.PENDING.value,
                            attempts=0,
                            available_at=now,
                        )
                        .on_conflict_do_nothing(index_elements=[OutboxEvent.idempotency_key])
                        .returning(OutboxEvent.id)
                    )
                ).scalar_one_or_none()
                inserted_count += inserted is not None
            return inserted_count


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
