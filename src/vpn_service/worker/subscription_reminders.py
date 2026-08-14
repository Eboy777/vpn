from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
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
                        or_(
                            (
                                (User.subscription_expires_at > now)
                                & (User.subscription_expires_at <= now + timedelta(days=3))
                            ),
                            (
                                (User.trial_expires_at > now)
                                & (User.trial_expires_at <= now + timedelta(hours=1))
                            ),
                        ),
                    )
                )
            ).all()
            inserted_count = 0
            for user in users:
                paid_expiry = user.subscription_expires_at
                if paid_expiry is not None and paid_expiry > now:
                    expiry = paid_expiry
                    stage = _paid_reminder_stage(expiry - now)
                    reminder_kind = "subscription"
                else:
                    expiry = user.trial_expires_at
                    stage = "1h" if expiry is not None and expiry > now else None
                    reminder_kind = "trial"
                if expiry is None or stage is None:
                    continue
                expiry_key = int(expiry.timestamp())
                inserted = (
                    await session.execute(
                        insert(OutboxEvent)
                        .values(
                            id=uuid.uuid4(),
                            event_type="telegram.call",
                            aggregate_type="telegram_user",
                            aggregate_id=user.id,
                            idempotency_key=_idempotency_key(
                                user.id,
                                expiry_key,
                                stage,
                                reminder_kind,
                            ),
                            payload_json={
                                "method": "sendMessage",
                                "params": {
                                    "chat_id": user.telegram_id,
                                    "text": _reminder_text(stage),
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


def _paid_reminder_stage(remaining: timedelta) -> str | None:
    if remaining <= timedelta(hours=1):
        return "1h"
    if remaining <= timedelta(days=1):
        return "1d"
    if remaining <= timedelta(days=3):
        return "3d"
    return None


def _reminder_text(stage: str) -> str:
    if stage == "1h":
        return (
            "Доступ к VPN закончится менее чем через час. "
            "Оплатите подписку, чтобы VPN продолжил работать без перерыва."
        )
    days = 1 if stage == "1d" else 3
    return f"Подписка закончится через {days} {'день' if days == 1 else 'дня'}."


def _idempotency_key(
    user_id: uuid.UUID,
    expiry_key: int,
    stage: str,
    reminder_kind: str,
) -> str:
    if reminder_kind == "subscription" and stage in {"1d", "3d"}:
        return f"telegram:subscription-expiry:{user_id}:{expiry_key}:{stage}"
    return f"telegram:access-expiry:{user_id}:{expiry_key}:{stage}"


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
