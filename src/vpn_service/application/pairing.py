from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.enums import DeviceStatus, NodeStatus, UserStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.schemas import TelegramUpdateRequest
from vpn_service.persistence.models import Device, Node, TelegramUpdateEvent, User
from vpn_service.persistence.rate_limits import RateLimitDecision, consume_rate_limit
from vpn_service.security.credentials import ProxyCredentialsCipher
from vpn_service.security.tokens import TokenHasher


@dataclass(frozen=True, slots=True)
class PairingInitResult:
    created: bool
    device_id: uuid.UUID
    pairing_session_token: str
    telegram_url: str
    expires_at: datetime
    poll_after_seconds: int


@dataclass(frozen=True, slots=True)
class PairingPendingResult:
    expires_at: datetime
    poll_after_seconds: int


@dataclass(frozen=True, slots=True)
class PairingPairedResult:
    device_id: uuid.UUID
    device_token: str


PairingStatusResult = PairingPendingResult | PairingPairedResult


class PairingService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._tokens = TokenHasher(settings)
        self._credentials = ProxyCredentialsCipher(settings)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def initialize(self, device_id: uuid.UUID, source_ip: str) -> PairingInitResult:
        username = self._settings.telegram_bot_username
        if username is None:
            raise ApplicationError(503, "PAIRING_UNAVAILABLE", "Pairing is unavailable")

        rate_now = self._now()
        subject = self._tokens.opaque_subject("pairing-init", f"{source_ip}:{device_id}")
        await self._enforce_init_rate_limits(subject, rate_now)

        session_token = self._tokens.issue("pairing_session")
        start_token = self._tokens.issue("telegram_start")

        async with self._sessions.begin() as session:
            now = await _transaction_now(session)
            expires_at = now + timedelta(seconds=self._settings.pairing_token_ttl_seconds)
            inserted_id = (
                await session.execute(
                    insert(Device)
                    .values(
                        id=uuid.uuid4(),
                        device_id=device_id,
                        status=DeviceStatus.PENDING.value,
                    )
                    .on_conflict_do_nothing(index_elements=[Device.device_id])
                    .returning(Device.id)
                )
            ).scalar_one_or_none()
            device = (
                await session.execute(
                    select(Device).where(Device.device_id == device_id).with_for_update()
                )
            ).scalar_one()
            if device.status == DeviceStatus.ACTIVE.value:
                raise ApplicationError(409, "DEVICE_ALREADY_PAIRED", "Device is already paired")
            if device.status == DeviceStatus.REVOKED.value:
                raise ApplicationError(409, "DEVICE_REVOKED", "Device is revoked")

            device.pairing_session_token_hash = session_token.digest
            device.pairing_session_token_key_id = session_token.key_id
            device.telegram_start_token_hash = start_token.digest
            device.telegram_start_token_key_id = start_token.key_id
            device.pairing_expires_at = expires_at
            device.pairing_error_code = None

        return PairingInitResult(
            created=inserted_id is not None,
            device_id=device_id,
            pairing_session_token=session_token.raw,
            telegram_url=f"https://t.me/{username}?start={start_token.raw}",
            expires_at=expires_at,
            poll_after_seconds=self._settings.pairing_poll_after_seconds,
        )

    async def status(
        self,
        *,
        device_id: uuid.UUID,
        pairing_session_token: str,
    ) -> PairingStatusResult:
        rate_now = self._now()
        subject = self._tokens.opaque_subject("pairing-status", pairing_session_token)
        await self._enforce_rate_limit(
            scope="pairing-status-minute",
            subject=subject,
            limit=self._settings.pairing_status_rate_per_minute,
            window_seconds=60,
            now=rate_now,
        )

        candidates = self._tokens.candidates("pairing_session", pairing_session_token)
        async with self._sessions.begin() as session:
            now = await _transaction_now(session)
            device = (
                await session.execute(
                    select(Device)
                    .where(_token_predicate(Device, "pairing_session", candidates))
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if device is None or device.device_id != device_id:
                raise ApplicationError(
                    401,
                    "INVALID_PAIRING_SESSION_TOKEN",
                    "Pairing session token is invalid",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if device.pairing_expires_at is None or device.pairing_expires_at <= now:
                raise ApplicationError(410, "PAIRING_EXPIRED", "Pairing session has expired")
            if device.pairing_error_code == "DEVICE_LIMIT_REACHED":
                raise ApplicationError(409, "DEVICE_LIMIT_REACHED", "Device limit reached")
            if device.status == DeviceStatus.PENDING.value:
                return PairingPendingResult(
                    expires_at=device.pairing_expires_at,
                    poll_after_seconds=self._settings.pairing_poll_after_seconds,
                )
            if device.status != DeviceStatus.ACTIVE.value or device.user_id is None:
                raise ApplicationError(
                    401,
                    "INVALID_PAIRING_SESSION_TOKEN",
                    "Pairing session token is invalid",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            device_token = self._tokens.issue("device")
            device.device_token_hash = device_token.digest
            device.device_token_key_id = device_token.key_id
            return PairingPairedResult(device_id=device.device_id, device_token=device_token.raw)

    async def process_telegram_update(self, update: TelegramUpdateRequest) -> str:
        start_token = _telegram_start_token(update, self._settings.telegram_bot_username)
        async with self._sessions.begin() as session:
            now = await _transaction_now(session)
            inserted = (
                await session.execute(
                    insert(TelegramUpdateEvent)
                    .values(
                        update_id=update.update_id,
                        received_at=now,
                        result_code="processing",
                    )
                    .on_conflict_do_nothing(index_elements=[TelegramUpdateEvent.update_id])
                    .returning(TelegramUpdateEvent.update_id)
                )
            ).scalar_one_or_none()
            if inserted is None:
                return "duplicate"
            event = await session.get(TelegramUpdateEvent, update.update_id)
            assert event is not None

            if start_token is None:
                _finish_telegram_event(event, now, "ignored")
                return "ignored"

            candidates = self._tokens.candidates("telegram_start", start_token)
            candidate_device = (
                await session.execute(
                    select(Device).where(_token_predicate(Device, "telegram_start", candidates))
                )
            ).scalar_one_or_none()
            if not _is_usable_start_device(candidate_device, now):
                _finish_telegram_event(event, now, "token_invalid")
                return "token_invalid"
            assert candidate_device is not None

            user, user_created = await self._lock_or_create_user(
                session,
                telegram_id=update.message.from_user.id,
                now=now,
            )
            device = (
                await session.execute(
                    select(Device).where(Device.id == candidate_device.id).with_for_update()
                )
            ).scalar_one()
            if not _is_usable_start_device(device, now) or not _matches_token(
                device,
                "telegram_start",
                candidates,
            ):
                if user_created:
                    await session.delete(user)
                _finish_telegram_event(event, now, "token_invalid")
                return "token_invalid"

            active_devices = int(
                (
                    await session.execute(
                        select(func.count(Device.id)).where(
                            Device.user_id == user.id,
                            Device.status == DeviceStatus.ACTIVE.value,
                        )
                    )
                ).scalar_one()
            )
            if active_devices >= self._settings.device_limit_per_user:
                device.user_id = user.id
                device.pairing_error_code = "DEVICE_LIMIT_REACHED"
                _consume_start_token(device)
                _finish_telegram_event(event, now, "device_limit_reached")
                return "device_limit_reached"

            if user.assigned_node_id is None:
                user.assigned_node_id = await self._choose_node(session, now)
            device.user_id = user.id
            device.status = DeviceStatus.ACTIVE.value
            device.pairing_error_code = None
            _consume_start_token(device)
            _finish_telegram_event(event, now, "paired")
            return "paired"

    async def _lock_or_create_user(
        self,
        session: AsyncSession,
        *,
        telegram_id: int,
        now: datetime,
    ) -> tuple[User, bool]:
        existing = (
            await session.execute(
                select(User).where(User.telegram_id == telegram_id).with_for_update()
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False

        user_id = uuid.uuid4()
        credentials = self._credentials.generate(user_id)
        inserted = (
            await session.execute(
                insert(User)
                .values(
                    id=user_id,
                    telegram_id=telegram_id,
                    status=UserStatus.ACTIVE.value,
                    trial_expires_at=now + timedelta(seconds=self._settings.trial_duration_seconds),
                    proxy_username=credentials.username,
                    proxy_password_ciphertext=credentials.password_ciphertext,
                    proxy_password_key_id=credentials.key_id,
                )
                .on_conflict_do_nothing(index_elements=[User.telegram_id])
                .returning(User.id)
            )
        ).scalar_one_or_none()
        if inserted is not None:
            created = await session.get(User, inserted)
            assert created is not None
            return created, True
        concurrent = (
            await session.execute(
                select(User).where(User.telegram_id == telegram_id).with_for_update()
            )
        ).scalar_one()
        return concurrent, False

    async def _choose_node(self, session: AsyncSession, now: datetime) -> uuid.UUID | None:
        nodes = list(
            (
                await session.scalars(
                    select(Node)
                    .where(Node.status == NodeStatus.ACTIVE.value)
                    .order_by(Node.id)
                    .with_for_update()
                )
            ).all()
        )
        if not nodes:
            return None
        loads = dict(
            (
                await session.execute(
                    select(User.assigned_node_id, func.count(User.id))
                    .where(
                        User.status == UserStatus.ACTIVE.value,
                        User.assigned_node_id.is_not(None),
                        or_(
                            User.trial_expires_at > now,
                            User.subscription_expires_at > now,
                        ),
                    )
                    .group_by(User.assigned_node_id)
                )
            ).all()
        )
        eligible = [node for node in nodes if int(loads.get(node.id, 0)) < node.capacity_users]
        if not eligible:
            return None
        selected = min(
            eligible,
            key=lambda node: (int(loads.get(node.id, 0)) / node.capacity_users, node.id),
        )
        return selected.id

    async def _enforce_init_rate_limits(self, subject: bytes, now: datetime) -> None:
        minute = await self._consume_rate_limit(
            "pairing-init-minute",
            subject,
            self._settings.pairing_init_rate_per_minute,
            60,
            now,
        )
        hour = await self._consume_rate_limit(
            "pairing-init-hour",
            subject,
            self._settings.pairing_init_rate_per_hour,
            3600,
            now,
        )
        decision = minute if not minute.allowed else hour
        if not decision.allowed:
            _raise_rate_limited(decision)

    async def _enforce_rate_limit(
        self,
        *,
        scope: str,
        subject: bytes,
        limit: int,
        window_seconds: int,
        now: datetime,
    ) -> None:
        decision = await self._consume_rate_limit(
            scope,
            subject,
            limit,
            window_seconds,
            now,
        )
        if not decision.allowed:
            _raise_rate_limited(decision)

    async def _consume_rate_limit(
        self,
        scope: str,
        subject: bytes,
        limit: int,
        window_seconds: int,
        now: datetime,
    ) -> RateLimitDecision:
        async with self._sessions.begin() as session:
            return await consume_rate_limit(
                session,
                scope=scope,
                subject_hash=subject,
                limit=limit,
                window_seconds=window_seconds,
                now=now,
            )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise RuntimeError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


def _token_predicate(model: type[Device], domain: str, candidates: list[tuple[str, bytes]]):
    hash_column = getattr(model, f"{domain}_token_hash")
    key_column = getattr(model, f"{domain}_token_key_id")
    return or_(
        *(and_(key_column == key_id, hash_column == digest) for key_id, digest in candidates)
    )


def _matches_token(device: Device, domain: str, candidates: list[tuple[str, bytes]]) -> bool:
    stored_hash = getattr(device, f"{domain}_token_hash")
    stored_key = getattr(device, f"{domain}_token_key_id")
    return any(stored_key == key_id and stored_hash == digest for key_id, digest in candidates)


def _is_usable_start_device(device: Device | None, now: datetime) -> bool:
    return bool(
        device is not None
        and device.status == DeviceStatus.PENDING.value
        and device.telegram_start_token_hash is not None
        and device.pairing_expires_at is not None
        and device.pairing_expires_at > now
    )


def _consume_start_token(device: Device) -> None:
    device.telegram_start_token_hash = None
    device.telegram_start_token_key_id = None


def _finish_telegram_event(
    event: TelegramUpdateEvent,
    now: datetime,
    result_code: str,
) -> None:
    event.processed_at = now
    event.result_code = result_code


def _telegram_start_token(
    update: TelegramUpdateRequest,
    bot_username: str | None,
) -> str | None:
    if bot_username is None:
        return None
    text = update.message.text
    match = re.fullmatch(
        rf"(/start(?:@{re.escape(bot_username)})?)[ ]+([A-Za-z0-9_-]{{43}})",
        text,
    )
    if match is None:
        return None
    command = match.group(1)
    expected_length = len(command.encode("utf-16-le")) // 2
    if not any(
        entity.type == "bot_command" and entity.offset == 0 and entity.length == expected_length
        for entity in update.message.entities
    ):
        return None
    return match.group(2)


def _raise_rate_limited(decision: RateLimitDecision) -> None:
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


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
