from __future__ import annotations

import hashlib
import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.pairing import PairingService
from vpn_service.application.payments import PaymentService
from vpn_service.config import Settings, TariffSettings
from vpn_service.domain.enums import DeviceStatus, OutboxStatus, PaymentStatus, UserStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.schemas import TelegramCallbackQuery, TelegramMessage, TelegramUpdateRequest
from vpn_service.persistence.models import Device, OutboxEvent, Payment, TelegramUpdateEvent, User
from vpn_service.security.credentials import ProxyCredentialsCipher

_PAIRING_START = re.compile(r"^/start(?:@[A-Za-z0-9_]{5,32})? [A-Za-z0-9_-]{43}$")


@dataclass(frozen=True, slots=True)
class TelegramAction:
    method: str
    params: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ProfileView:
    telegram_id: int
    tariff_name: str | None
    access_kind: str | None
    started_at: datetime | None
    expires_at: datetime | None
    remaining_days: int | None

    @property
    def has_access(self) -> bool:
        return self.expires_at is not None


@dataclass(frozen=True, slots=True)
class DeviceView:
    id: uuid.UUID
    last_seen_at: datetime | None
    created_at: datetime

    @property
    def activity_at(self) -> datetime:
        return self.last_seen_at or self.created_at


class TelegramBotService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
        pairing_service: PairingService,
        payment_service: PaymentService | None = None,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._pairing_service = pairing_service
        self._payment_service = payment_service
        self._credentials = ProxyCredentialsCipher(settings)

    async def process_update(self, update: TelegramUpdateRequest) -> str:
        if _is_pairing_start(update):
            return await self._process_pairing_start(update)

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
            telegram_user = _update_user(update)
            user, _created = await self._lock_or_create_user(
                session,
                telegram_id=telegram_user.id,
                now=now,
            )
            actions = await self._actions_for_update(
                session,
                update=update,
                user=user,
                now=now,
            )
            await _enqueue_actions(
                session,
                update_id=update.update_id,
                user_id=user.id,
                actions=actions,
                now=now,
            )
            event.processed_at = now
            event.result_code = "bot_processed"
            return "processed"

    async def _process_pairing_start(self, update: TelegramUpdateRequest) -> str:
        await self._pairing_service.process_telegram_update(update)
        assert update.message is not None
        async with self._sessions.begin() as session:
            now = await _transaction_now(session)
            event = await session.get(TelegramUpdateEvent, update.update_id)
            result = event.result_code if event is not None else "token_invalid"
            user = await session.scalar(
                select(User).where(User.telegram_id == update.message.from_user.id)
            )
            actions: list[TelegramAction]
            if result == "paired" and user is not None:
                profile = await self._profile(session, user, now)
                actions = [
                    _send(
                        update.message.chat.id,
                        "✅ Устройство привязано. VPN готов к подключению.",
                    ),
                    _send_profile(
                        update.message.chat.id,
                        profile,
                        self._settings,
                        ensure_reply_keyboard=True,
                    ),
                ]
            elif result == "device_limit_reached":
                actions = [
                    _send(
                        update.message.chat.id,
                        "Не удалось привязать устройство: достигнут лимит устройств тарифа.",
                        reply_markup=reply_keyboard(),
                    )
                ]
            else:
                actions = [
                    _send(
                        update.message.chat.id,
                        "Ссылка привязки недействительна или уже использована. "
                        "Создайте новую ссылку в расширении.",
                        reply_markup=reply_keyboard(),
                    )
                ]
            await _enqueue_actions(
                session,
                update_id=update.update_id,
                user_id=user.id if user is not None else None,
                actions=actions,
                now=now,
            )
        return result

    async def _actions_for_update(
        self,
        session: AsyncSession,
        *,
        update: TelegramUpdateRequest,
        user: User,
        now: datetime,
    ) -> list[TelegramAction]:
        profile = await self._profile(session, user, now)
        if update.message is not None:
            return self._message_actions(
                update.message,
                profile=profile,
            )
        assert update.callback_query is not None
        return await self._callback_actions(
            update.callback_query,
            session=session,
            user=user,
            profile=profile,
            now=now,
        )

    def _message_actions(
        self,
        message: TelegramMessage,
        *,
        profile: ProfileView,
    ) -> list[TelegramAction]:
        text = (message.text or "").strip()
        if re.fullmatch(r"/start(?:@[A-Za-z0-9_]{5,32})? support", text):
            return [_send_support(message.chat.id, profile.telegram_id, self._settings)]
        if text.startswith("/start"):
            return [_send_welcome(message.chat.id, self._settings)]
        if text in {"⚡ Подключить VPN", "⚡️ Подключить VPN"}:
            return [_send_connect_hub(message.chat.id, profile, self._settings)]
        if text == "👤 Мой профиль":
            return [_send_profile(message.chat.id, profile, self._settings)]
        if text == "💬 Поддержка":
            return [_send_support(message.chat.id, profile.telegram_id, self._settings)]
        return [_send_profile(message.chat.id, profile, self._settings)]

    async def _callback_actions(
        self,
        callback: TelegramCallbackQuery,
        *,
        session: AsyncSession,
        user: User,
        profile: ProfileView,
        now: datetime,
    ) -> list[TelegramAction]:
        actions = [
            TelegramAction(
                "answerCallbackQuery",
                {"callback_query_id": callback.id},
            )
        ]
        if callback.message is None or callback.data is None:
            return actions

        chat_id = callback.message.chat.id
        message_id = callback.message.message_id
        data = callback.data
        if data == "menu:profile":
            actions.append(_send_profile(chat_id, profile, self._settings))
        elif data == "menu:connect":
            actions.append(_edit_connect_hub(chat_id, message_id, profile, self._settings))
        elif data == "menu:tariffs":
            if callback.message.text is None:
                actions.append(_send_tariffs(chat_id, self._settings))
            else:
                actions.append(_edit_tariffs(chat_id, message_id, self._settings))
        elif data == "support:list":
            actions.append(_edit_support(chat_id, message_id, profile.telegram_id, self._settings))
        elif data == "support:faq":
            actions.append(_edit_faq_menu(chat_id, message_id, profile.telegram_id, self._settings))
        elif data.startswith("faq:"):
            actions.append(
                _edit_faq(
                    chat_id,
                    message_id,
                    data.removeprefix("faq:"),
                    profile.telegram_id,
                    self._settings,
                )
            )
        elif data == "phone:setup":
            actions.append(_send_phone_placeholder(chat_id))
        elif data in {"phone:retry", "phone:unavailable"}:
            actions.append(_edit_phone_placeholder(chat_id, message_id))
        elif data == "subscription:manage":
            actions.append(
                _send_subscription_management(
                    chat_id,
                    profile.telegram_id,
                    self._settings,
                )
            )
        elif data == "subscription:cancel":
            if self._payment_service is None:
                actions.append(_edit_payment_error(chat_id, message_id))
            else:
                try:
                    cancelled = await self._payment_service.cancel(user_id=user.id)
                except ApplicationError:
                    actions.append(_edit_payment_error(chat_id, message_id))
                else:
                    actions.append(_edit_subscription_cancelled(chat_id, message_id, cancelled))
        elif data == "devices:list":
            devices = await self._active_devices(session, user)
            if callback.message.text is None:
                actions.append(_send_devices(chat_id, devices))
            else:
                actions.append(_edit_devices(chat_id, message_id, devices))
        elif data.startswith("device:select:"):
            device_id = _callback_uuid(data, "device:select:")
            device = await self._active_device(session, user, device_id)
            actions.append(_edit_device_confirmation(chat_id, message_id, device))
        elif data.startswith("device:revoke:"):
            device_id = _callback_uuid(data, "device:revoke:")
            revoked = await self._revoke_device(session, user, device_id)
            devices = await self._active_devices(session, user)
            actions.append(_edit_device_revoked(chat_id, message_id, devices, revoked))
        elif data == "menu:main":
            actions.append(_send_welcome(chat_id, self._settings))
        elif data.startswith("tariff:"):
            code = data.removeprefix("tariff:")
            actions.append(
                _edit_payment(
                    chat_id,
                    message_id,
                    code,
                    profile,
                    now,
                    self._settings,
                )
            )
        elif data.startswith("payment:"):
            code = data.removeprefix("payment:")
            offer = self._settings.lava_offers_json.get(code)
            if self._payment_service is None or offer is None:
                actions.append(_edit_payment_placeholder(chat_id, message_id, code, self._settings))
            else:
                idempotency_key = "telegram:" + hashlib.sha256(callback.id.encode()).hexdigest()
                try:
                    payment = await self._payment_service.create(
                        user_id=user.id,
                        tariff_code=code,
                        idempotency_key=idempotency_key,
                        email=None,
                        terms_accepted=True,
                        recurring_consent=offer.periodicity != "ONE_TIME",
                    )
                except ApplicationError:
                    actions.append(_edit_payment_error(chat_id, message_id))
                else:
                    actions.append(
                        _edit_payment_link(
                            chat_id,
                            message_id,
                            payment.payment_url,
                            recurring=offer.periodicity != "ONE_TIME",
                        )
                    )
        else:
            actions.append(_edit_profile(chat_id, message_id, profile, self._settings))
        return actions

    async def _active_devices(self, session: AsyncSession, user: User) -> list[DeviceView]:
        rows = (
            await session.scalars(
                select(Device)
                .where(
                    Device.user_id == user.id,
                    Device.status == DeviceStatus.ACTIVE.value,
                )
                .order_by(Device.last_seen_at.desc().nullslast(), Device.created_at.desc())
            )
        ).all()
        return [DeviceView(row.id, row.last_seen_at, row.created_at) for row in rows]

    async def _active_device(
        self,
        session: AsyncSession,
        user: User,
        device_id: uuid.UUID | None,
    ) -> DeviceView | None:
        if device_id is None:
            return None
        row = await session.scalar(
            select(Device).where(
                Device.id == device_id,
                Device.user_id == user.id,
                Device.status == DeviceStatus.ACTIVE.value,
            )
        )
        if row is None:
            return None
        return DeviceView(row.id, row.last_seen_at, row.created_at)

    async def _revoke_device(
        self,
        session: AsyncSession,
        user: User,
        device_id: uuid.UUID | None,
    ) -> bool:
        if device_id is None:
            return False
        row = await session.scalar(
            select(Device)
            .where(
                Device.id == device_id,
                Device.user_id == user.id,
                Device.status == DeviceStatus.ACTIVE.value,
            )
            .with_for_update()
        )
        if row is None:
            return False
        row.status = DeviceStatus.REVOKED.value
        row.pairing_session_token_hash = None
        row.pairing_session_token_key_id = None
        row.telegram_start_token_hash = None
        row.telegram_start_token_key_id = None
        row.pairing_expires_at = None
        row.pairing_error_code = None
        return True

    async def _profile(
        self,
        session: AsyncSession,
        user: User,
        now: datetime,
    ) -> ProfileView:
        latest_paid_payment = await session.scalar(
            select(Payment)
            .where(
                Payment.user_id == user.id,
                Payment.status == PaymentStatus.PAID.value,
            )
            .order_by(Payment.paid_at.desc(), Payment.created_at.desc())
            .limit(1)
        )
        if user.subscription_expires_at is not None and user.subscription_expires_at > now:
            expires_at = user.subscription_expires_at
            tariff_code = latest_paid_payment.tariff_code if latest_paid_payment else "flow_1m"
            tariff = self._settings.tariffs_json.get(tariff_code)
            started_at = latest_paid_payment.paid_at if latest_paid_payment else None
            if started_at is None and tariff is not None:
                started_at = expires_at - timedelta(days=tariff.period_days)
            return ProfileView(
                telegram_id=user.telegram_id,
                tariff_name=tariff_name(tariff_code),
                access_kind="paid",
                started_at=started_at,
                expires_at=expires_at,
                remaining_days=_remaining_days(now, expires_at),
            )
        if user.trial_expires_at is not None and user.trial_expires_at > now:
            expires_at = user.trial_expires_at
            return ProfileView(
                telegram_id=user.telegram_id,
                tariff_name="Пробный доступ",
                access_kind="trial",
                started_at=expires_at - timedelta(seconds=self._settings.trial_duration_seconds),
                expires_at=expires_at,
                remaining_days=_remaining_days(now, expires_at),
            )
        return ProfileView(
            telegram_id=user.telegram_id,
            tariff_name=None,
            access_kind=None,
            started_at=None,
            expires_at=None,
            remaining_days=None,
        )

    async def _lock_or_create_user(
        self,
        session: AsyncSession,
        *,
        telegram_id: int,
        now: datetime,
    ) -> tuple[User, bool]:
        existing = await session.scalar(
            select(User).where(User.telegram_id == telegram_id).with_for_update()
        )
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
                    trial_expires_at=None,
                    proxy_username=credentials.username,
                    proxy_password_ciphertext=credentials.password_ciphertext,
                    proxy_password_key_id=credentials.key_id,
                    created_at=now,
                )
                .on_conflict_do_nothing(index_elements=[User.telegram_id])
                .returning(User.id)
            )
        ).scalar_one_or_none()
        if inserted is not None:
            created = await session.get(User, inserted)
            assert created is not None
            return created, True
        concurrent = await session.scalar(
            select(User).where(User.telegram_id == telegram_id).with_for_update()
        )
        assert concurrent is not None
        return concurrent, False


def reply_keyboard() -> dict[str, Any]:
    return {
        "keyboard": [
            [{"text": "⚡️ Подключить VPN"}],
            [{"text": "👤 Мой профиль"}, {"text": "💬 Поддержка"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


def profile_text(profile: ProfileView) -> str:
    lines = ["👤 Мой профиль", "", f"├ ‣ ID: {profile.telegram_id}"]
    if not profile.has_access:
        lines.extend(
            [
                "└ ‣ Тариф: Подписка не активна",
                "",
                "Выберите тарифный план, чтобы оформить доступ!",
            ]
        )
        return "\n".join(lines)
    assert profile.tariff_name is not None
    assert profile.expires_at is not None
    assert profile.remaining_days is not None
    started_at = (
        profile.started_at.astimezone(UTC).strftime("%d.%m.%Y")
        if profile.started_at is not None
        else "—"
    )
    lines.extend(
        [
            f"├ ‣ Тариф: {profile.tariff_name}",
            f"├ ‣ Дата начала: {started_at}",
            f"├ ‣ Дата окончания: {profile.expires_at.astimezone(UTC).strftime('%d.%m.%Y')}",
            f"└ ‣ Осталось: {profile.remaining_days} дн.",
            "",
            "Выберите нужное действие в меню ниже.",
        ]
    )
    return "\n".join(lines)


def profile_keyboard(profile: ProfileView, settings: Settings) -> dict[str, Any]:
    if not profile.has_access:
        return {
            "inline_keyboard": [
                [{"text": "⚡ Купить подписку", "callback_data": "menu:tariffs"}],
                [{"text": "📱 Мои устройства", "callback_data": "devices:list"}],
            ]
        }
    return {
        "inline_keyboard": [
            [{"text": "📱 Настроить на телефоне", "callback_data": "phone:setup"}],
            [{"text": "🌐 Настроить в браузере", "url": _chrome_url(settings)}],
            [{"text": "📱 Мои устройства", "callback_data": "devices:list"}],
            [
                {
                    "text": "⚙️ Управление подпиской",
                    "callback_data": "subscription:manage",
                }
            ],
        ]
    }


def _edit_devices(
    chat_id: int,
    message_id: int,
    devices: list[DeviceView],
) -> TelegramAction:
    if not devices:
        return _edit(
            chat_id,
            message_id,
            "📱 Мои устройства\n\nАктивных устройств нет. Привяжите расширение через Telegram.",
            {"inline_keyboard": [[{"text": "◀️ В профиль", "callback_data": "menu:profile"}]]},
        )
    lines = ["📱 Мои устройства", "", f"Активно: {len(devices)}", ""]
    rows: list[list[dict[str, str]]] = []
    for index, device in enumerate(devices, start=1):
        activity = device.activity_at.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")
        lines.append(f"{index}. Последняя активность: {activity}")
        rows.append(
            [
                {
                    "text": f"Отключить устройство {index}",
                    "callback_data": f"device:select:{device.id}",
                }
            ]
        )
    lines.extend(["", "Отключённое устройство потеряет доступ при следующей проверке."])
    rows.append([{"text": "◀️ В профиль", "callback_data": "menu:profile"}])
    return _edit(chat_id, message_id, "\n".join(lines), {"inline_keyboard": rows})


def _send_devices(chat_id: int, devices: list[DeviceView]) -> TelegramAction:
    editable = _edit_devices(chat_id, 0, devices)
    return _send(
        chat_id,
        editable.params["text"],
        reply_markup=editable.params["reply_markup"],
    )


def _edit_device_confirmation(
    chat_id: int,
    message_id: int,
    device: DeviceView | None,
) -> TelegramAction:
    if device is None:
        return _edit(
            chat_id,
            message_id,
            "Устройство уже отключено или не принадлежит вашему аккаунту.",
            {"inline_keyboard": [[{"text": "◀️ К устройствам", "callback_data": "devices:list"}]]},
        )
    activity = device.activity_at.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")
    return _edit(
        chat_id,
        message_id,
        "Отключить это устройство?\n\n"
        f"Последняя активность: {activity}\n\n"
        "Если это текущее устройство, VPN на нём отключится автоматически.",
        {
            "inline_keyboard": [
                [
                    {
                        "text": "Да, отключить",
                        "callback_data": f"device:revoke:{device.id}",
                    }
                ],
                [{"text": "◀️ Отмена", "callback_data": "devices:list"}],
            ]
        },
    )


def _edit_device_revoked(
    chat_id: int,
    message_id: int,
    devices: list[DeviceView],
    revoked: bool,
) -> TelegramAction:
    action = _edit_devices(chat_id, message_id, devices)
    prefix = "✅ Устройство отключено.\n\n" if revoked else "Устройство уже отключено.\n\n"
    return TelegramAction(action.method, {**action.params, "text": prefix + action.params["text"]})


def _callback_uuid(data: str, prefix: str) -> uuid.UUID | None:
    try:
        value = uuid.UUID(data.removeprefix(prefix))
    except (ValueError, AttributeError):
        return None
    return value if str(value) == data.removeprefix(prefix) else None


def tariff_name(code: str) -> str:
    names = {
        "vpn_15d": "Virgo TRIP",
        "vpn_30d": "Тестовый тариф Lava",
        "flow_1m": "Virgo FLOW · 1 месяц",
        "flow_3m": "Virgo FLOW · 3 месяца",
        "flow_6m": "Virgo FLOW · 6 месяцев",
        "space_1m": "Virgo SPACE · 1 месяц",
        "space_3m": "Virgo SPACE · 3 месяца",
        "space_6m": "Virgo SPACE · 6 месяцев",
    }
    return names.get(code, code.replace("_", " ").title())


def tariff_price(tariff: TariffSettings) -> str:
    rubles, kopecks = divmod(tariff.amount_minor, 100)
    formatted = f"{rubles:,}".replace(",", " ")
    return f"{formatted} ₽" if kopecks == 0 else f"{formatted},{kopecks:02d} ₽"


def tariffs_text(settings: Settings) -> str:
    sections = ["💳 Тарифы Virgo"]
    if any(code in settings.tariffs_json for code in ("flow_1m", "flow_3m", "flow_6m")):
        sections.append(
            "\nVirgo FLOW\n"
            "Лёгкий стартовый план для базовых задач и социальных сетей.\n"
            "• Быстрое подключение без ограничений\n"
            "• 4 устройства\n"
            "• Поддержка 24/7\n\n" + _tariff_price_lines(settings, "flow")
        )
    if any(code in settings.tariffs_json for code in ("space_1m", "space_3m", "space_6m")):
        sections.append(
            "\nVirgo SPACE — рекомендуем\n"
            "Максимальный комфорт, сглаживание задержек и полная свобода.\n"
            "• До 8 устройств\n"
            "• Максимальная скорость и выделенные линии\n"
            "• Автовыбор лучшего сервера\n\n" + _tariff_price_lines(settings, "space")
        )
    test_tariff = settings.tariffs_json.get("vpn_30d")
    if test_tariff is not None and test_tariff.enabled:
        sections.append(
            "\n🧪 Тестовый тариф Lava\n"
            "Только для технической проверки платежей, не публичный тариф."
        )
    return "\n".join(sections)


def _tariff_price_lines(settings: Settings, plan: str) -> str:
    labels = {"1m": "1 месяц", "3m": "3 месяца", "6m": "6 месяцев"}
    lines = []
    for period in ("1m", "3m", "6m"):
        tariff = settings.tariffs_json.get(f"{plan}_{period}")
        if tariff is not None and tariff.enabled:
            lines.append(f"{labels[period]} — {tariff_price(tariff)}")
    return "\n".join(lines)


def tariffs_keyboard(settings: Settings) -> dict[str, Any]:
    order = (
        "flow_1m",
        "flow_3m",
        "flow_6m",
        "space_1m",
        "space_3m",
        "space_6m",
        "vpn_30d",
    )
    rows = []
    for code in order:
        tariff = settings.tariffs_json.get(code)
        if tariff is None or not tariff.enabled:
            continue
        icon = "🧪" if code == "vpn_30d" else "⚡️" if code.startswith("flow") else "🚀"
        rows.append(
            [
                {
                    "text": f"{icon} {tariff_name(code)} — {tariff_price(tariff)}",
                    "callback_data": f"tariff:{code}",
                }
            ]
        )
    rows.append([{"text": "◀️ Назад", "callback_data": "menu:profile"}])
    return {"inline_keyboard": rows}


def support_text() -> str:
    return (
        "💬 Служба поддержки Virgo VPN\n\n"
        "Нажмите на нужный вопрос ниже, чтобы получить быстрый ответ, "
        "или свяжитесь с нашим оператором напрямую.\n\n"
        "❓ Частые вопросы:\n"
        "• Как установить расширение в браузер?\n"
        "• Как настроить VPN на телефоне?\n"
        "• Что делать, если снизилась скорость?\n"
        "• Как управлять подпиской?"
    )


def support_keyboard(telegram_id: int, settings: Settings) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "Ответы на вопросы (FAQ)", "callback_data": "support:faq"}],
            [{"text": "Написать оператору", "url": _support_url(telegram_id, settings)}],
            [{"text": "◀️ Главное меню", "callback_data": "menu:main"}],
        ]
    }


def welcome_text(settings: Settings) -> str:
    return (
        "Привет! 🛰\n\n"
        f"Добро пожаловать в {settings.vpn_brand_name} VPN. Мы создали этот сервис, "
        "чтобы интернет оставался открытым и комфортным для всех ваших устройств.\n\n"
        "Не отключайте бота — все технические новости, статус серверов и обновления "
        "вы найдёте тут!"
    )


def _send_welcome(chat_id: int, settings: Settings) -> TelegramAction:
    return _send_photo(
        chat_id,
        "welcome",
        welcome_text(settings),
        reply_keyboard_markup=reply_keyboard(),
    )


def _send_profile(
    chat_id: int,
    profile: ProfileView,
    settings: Settings,
    *,
    ensure_reply_keyboard: bool = False,
) -> TelegramAction:
    return _send_photo(
        chat_id,
        "profile",
        profile_text(profile),
        reply_markup=profile_keyboard(profile, settings),
        reply_keyboard_markup=reply_keyboard() if ensure_reply_keyboard else None,
    )


def _edit_profile(
    chat_id: int,
    message_id: int,
    profile: ProfileView,
    settings: Settings,
) -> TelegramAction:
    return _edit(chat_id, message_id, profile_text(profile), profile_keyboard(profile, settings))


def _send_connect_hub(
    chat_id: int,
    profile: ProfileView,
    settings: Settings,
) -> TelegramAction:
    text, markup = _connect_hub(profile, settings)
    if not profile.has_access:
        return _send_photo(chat_id, "welcome", text, reply_markup=markup)
    return _send(chat_id, text, reply_markup=markup)


def _edit_connect_hub(
    chat_id: int,
    message_id: int,
    profile: ProfileView,
    settings: Settings,
) -> TelegramAction:
    text, markup = _connect_hub(profile, settings)
    return _edit(chat_id, message_id, text, markup)


def _connect_hub(profile: ProfileView, settings: Settings) -> tuple[str, dict[str, Any]]:
    if not profile.has_access:
        return (
            "У вас нет активной подписки. Подключите тариф для доступа к VPN:",
            {
                "inline_keyboard": [
                    [{"text": "🛒 Купить подписку", "callback_data": "menu:tariffs"}],
                    [{"text": "🌐 Установить для браузера", "url": _chrome_url(settings)}],
                ]
            },
        )
    return (
        "Ваш VPN активен. Выберите устройство для настройки:",
        {
            "inline_keyboard": [
                [{"text": "📱 Настроить на телефоне", "callback_data": "phone:setup"}],
                [{"text": "🌐 Настроить в браузере", "url": _chrome_url(settings)}],
                [{"text": "⚙️ Управление подпиской", "callback_data": "menu:tariffs"}],
            ]
        },
    )


def _send_support(chat_id: int, telegram_id: int, settings: Settings) -> TelegramAction:
    return _send(chat_id, support_text(), reply_markup=support_keyboard(telegram_id, settings))


def _edit_support(
    chat_id: int,
    message_id: int,
    telegram_id: int,
    settings: Settings,
) -> TelegramAction:
    return _edit(
        chat_id,
        message_id,
        support_text(),
        support_keyboard(telegram_id, settings),
    )


def _edit_faq_menu(
    chat_id: int,
    message_id: int,
    telegram_id: int,
    settings: Settings,
) -> TelegramAction:
    return _edit(
        chat_id,
        message_id,
        "Выберите интересующую тему ниже, чтобы получить подробную инструкцию:",
        {
            "inline_keyboard": [
                [{"text": "🌐 Настройка в браузере", "callback_data": "faq:browser"}],
                [{"text": "📱 Настройка на телефоне", "callback_data": "faq:mobile"}],
                [{"text": "⚡️ Что делать при низкой скорости?", "callback_data": "faq:speed"}],
                [{"text": "💳 Автопродление и тарифы", "callback_data": "faq:billing"}],
                [
                    {
                        "text": "👤 Написать оператору",
                        "url": _support_url(telegram_id, settings),
                    }
                ],
                [{"text": "◀️ В меню поддержки", "callback_data": "support:list"}],
            ]
        },
    )


def _edit_faq(
    chat_id: int,
    message_id: int,
    topic: str,
    telegram_id: int,
    settings: Settings,
) -> TelegramAction:
    answers = {
        "browser": (
            "Подключение расширения для браузера\n\n"
            "1. Перейдите в Chrome Web Store по кнопке ниже и нажмите «Установить».\n"
            "2. Откройте расширение и выберите вход через Telegram.\n"
            "3. Подтвердите привязку в этом боте, вернитесь в расширение и нажмите "
            "«Подключиться»."
        ),
        "mobile": (
            "Подключение на смартфоне (iOS / Android)\n\n"
            "Мобильная настройка пока готовится. Кнопки скачивания и персональный "
            "конфиг появятся после подключения мобильного сервиса."
        ),
        "speed": (
            "Решение проблем со скоростью\n\n"
            "• Смените локацию на соседний сервер с меньшей задержкой.\n"
            "• Отключите и снова подключите VPN.\n"
            "• Если проблема сохраняется, напишите оператору."
        ),
        "billing": (
            "Управление подпиской и списаниями\n\n"
            "Если тариф оформлен с автопродлением, отменить его можно в боте: "
            "«Мой профиль» → «Управление подпиской» → «Отключить автопродление». "
            "После отмены новых списаний не будет, а уже оплаченный доступ продолжит "
            "действовать до указанной даты. Если кнопка не сработала, напишите оператору."
        ),
    }
    keyboards = {
        "browser": [
            [{"text": "• Подключить для браузера", "url": _chrome_url(settings)}],
        ],
        "mobile": [
            [{"text": "📱 Открыть настройку", "callback_data": "phone:setup"}],
        ],
        "speed": [],
        "billing": [
            [
                {
                    "text": "Управление подпиской",
                    "callback_data": "subscription:manage",
                }
            ],
        ],
    }
    rows = list(keyboards.get(topic, []))
    rows.extend(
        [
            [{"text": "Написать в поддержку", "url": _support_url(telegram_id, settings)}],
            [{"text": "◀️ К вопросам", "callback_data": "support:faq"}],
        ]
    )
    return _edit(
        chat_id,
        message_id,
        answers.get(topic, "Ответ пока не добавлен."),
        {"inline_keyboard": rows},
    )


def _phone_placeholder_text() -> str:
    return (
        "Настройка VPN на смартфоне (Android / iOS)\n\n"
        "Мобильное подключение пока готовится. Ссылки на приложение и персональный "
        "конфиг появятся здесь после подключения мобильного сервиса.\n\n"
        "Если возникнут вопросы — наша поддержка всегда на связи."
    )


def _phone_placeholder_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "• Скачать Happ для iOS", "callback_data": "phone:unavailable"}],
            [{"text": "• Скачать Happ для Android", "callback_data": "phone:unavailable"}],
            [
                {
                    "text": "🔗 Скопировать ключ / Конфиг",
                    "callback_data": "phone:unavailable",
                }
            ],
            [{"text": "◀️ Назад", "callback_data": "menu:connect"}],
        ]
    }


def _send_phone_placeholder(chat_id: int) -> TelegramAction:
    return _send(
        chat_id,
        _phone_placeholder_text(),
        reply_markup=_phone_placeholder_keyboard(),
    )


def _edit_phone_placeholder(chat_id: int, message_id: int) -> TelegramAction:
    return _edit(
        chat_id,
        message_id,
        _phone_placeholder_text(),
        _phone_placeholder_keyboard(),
    )


def _send_subscription_management(
    chat_id: int,
    telegram_id: int,
    settings: Settings,
) -> TelegramAction:
    return _send(
        chat_id,
        "⚙️ Управление подпиской\n\n"
        "Здесь можно сменить тариф или отключить дальнейшие автоматические списания. "
        "После отмены уже оплаченный доступ действует до даты окончания.",
        reply_markup={
            "inline_keyboard": [
                [{"text": "Продлить / Сменить тариф", "callback_data": "menu:tariffs"}],
                [
                    {
                        "text": "Отключить автопродление",
                        "callback_data": "subscription:cancel",
                    }
                ],
                [{"text": "Написать оператору", "url": _support_url(telegram_id, settings)}],
                [{"text": "◀️ Назад в профиль", "callback_data": "menu:profile"}],
            ]
        },
    )


def _edit_tariffs(chat_id: int, message_id: int, settings: Settings) -> TelegramAction:
    return _edit(chat_id, message_id, tariffs_text(settings), tariffs_keyboard(settings))


def _send_tariffs(chat_id: int, settings: Settings) -> TelegramAction:
    return _send(chat_id, tariffs_text(settings), reply_markup=tariffs_keyboard(settings))


def _edit_payment(
    chat_id: int,
    message_id: int,
    code: str,
    profile: ProfileView,
    now: datetime,
    settings: Settings,
) -> TelegramAction:
    tariff = settings.tariffs_json.get(code)
    if tariff is None or not tariff.enabled:
        return _edit(
            chat_id,
            message_id,
            "Тариф недоступен.",
            {"inline_keyboard": [[{"text": "◀️ Назад", "callback_data": "menu:tariffs"}]]},
        )
    offer = settings.lava_offers_json.get(code)
    recurring = offer is not None and offer.periodicity != "ONE_TIME"
    renewal_note = (
        "Оплата включает автопродление с указанной периодичностью. Его можно отключить "
        "в профиле бота; оплаченный срок при этом сохранится. Нажимая кнопку оплаты, "
        "вы принимаете условия подписки и соглашаетесь на регулярные списания."
        if recurring
        else "Это разовая оплата без автоматического продления."
    )
    rows: list[list[dict[str, str]]] = [
        [
            {
                "text": "💳 Оплатить и включить автопродление" if recurring else "💳 Оплатить",
                "callback_data": f"payment:{code}",
            }
        ],
    ]
    if settings.legal_documents_base_url is not None:
        rows.extend(
            [
                [
                    {
                        "text": "Пользовательское соглашение",
                        "url": _legal_url(settings, "user-agreement"),
                    },
                    {
                        "text": "Автопродление",
                        "url": _legal_url(settings, "recurring-payment-consent"),
                    },
                ],
                [
                    {
                        "text": "Конфиденциальность",
                        "url": _legal_url(settings, "privacy-policy"),
                    },
                    {
                        "text": "Отмена и возврат",
                        "url": _legal_url(settings, "refund-and-cancellation"),
                    },
                ],
            ]
        )
    rows.append([{"text": "◀️ Выбрать другой тариф", "callback_data": "menu:tariffs"}])
    if offer is not None:
        payment_terms = (
            f"Вы выбрали тариф {tariff_name(code)}.\n\n"
            "Точная цена, период подписки и дата следующего списания будут показаны "
            "на странице оплаты Lava до подтверждения платежа.\n\n"
        )
    else:
        period_start = (
            profile.expires_at if profile.expires_at and profile.expires_at > now else now
        )
        period_end = period_start + timedelta(days=tariff.period_days)
        payment_terms = (
            f"Вы выбрали тариф {tariff_name(code)} на {tariff.period_days} дней.\n\n"
            f"├ ‣ Период: до {period_end.astimezone(UTC).strftime('%d.%m.%Y')}\n"
            f"└ ‣ К оплате: {tariff_price(tariff)}\n\n"
        )
    return _edit(
        chat_id,
        message_id,
        f"{payment_terms}{renewal_note}",
        {"inline_keyboard": rows},
    )


def _edit_payment_placeholder(
    chat_id: int,
    message_id: int,
    code: str,
    settings: Settings,
) -> TelegramAction:
    tariff = settings.tariffs_json.get(code)
    title = tariff_name(code)
    price = tariff_price(tariff) if tariff is not None else "—"
    return _edit(
        chat_id,
        message_id,
        f"Оплата тарифа {title} ({price}) пока отключена. "
        "Ссылка появится после подключения тестового эквайринга.",
        {"inline_keyboard": [[{"text": "◀️ Назад", "callback_data": "menu:tariffs"}]]},
    )


def _edit_payment_link(
    chat_id: int,
    message_id: int,
    payment_url: str,
    *,
    recurring: bool,
) -> TelegramAction:
    note = (
        "На странице Lava проверьте сумму и период автопродления перед подтверждением."
        if recurring
        else "На странице Lava проверьте сумму перед подтверждением."
    )
    return _edit(
        chat_id,
        message_id,
        "Платёжная ссылка готова. " + note,
        {
            "inline_keyboard": [
                [{"text": "Перейти к безопасной оплате", "url": payment_url}],
                [{"text": "◀️ Назад к тарифам", "callback_data": "menu:tariffs"}],
            ]
        },
    )


def _edit_payment_error(chat_id: int, message_id: int) -> TelegramAction:
    return _edit(
        chat_id,
        message_id,
        "Не удалось подготовить оплату. Попробуйте ещё раз позже или напишите оператору.",
        {"inline_keyboard": [[{"text": "◀️ Назад", "callback_data": "menu:tariffs"}]]},
    )


def _edit_subscription_cancelled(
    chat_id: int,
    message_id: int,
    cancelled: bool,
) -> TelegramAction:
    text = (
        "Автопродление отключено. Новых списаний не будет, а оплаченный доступ "
        "сохранится до даты окончания."
        if cancelled
        else "Активная подписка с автопродлением не найдена."
    )
    return _edit(
        chat_id,
        message_id,
        text,
        {"inline_keyboard": [[{"text": "◀️ В профиль", "callback_data": "menu:profile"}]]},
    )


def _send(
    chat_id: int,
    text: str,
    *,
    reply_markup: dict[str, Any] | None = None,
    reply_keyboard_markup: dict[str, Any] | None = None,
) -> TelegramAction:
    params: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        params["reply_markup"] = reply_markup
    if reply_keyboard_markup is not None:
        # Telegram accepts only one markup. The persistent reply keyboard is sent as a short
        # companion message so the profile can keep its inline actions.
        params["reply_markup"] = reply_markup
        params["_reply_keyboard"] = reply_keyboard_markup
    return TelegramAction("sendMessage", params)


def _send_photo(
    chat_id: int,
    photo_asset: str,
    caption: str,
    *,
    reply_markup: dict[str, Any] | None = None,
    reply_keyboard_markup: dict[str, Any] | None = None,
) -> TelegramAction:
    params: dict[str, Any] = {
        "chat_id": chat_id,
        "photo_asset": photo_asset,
        "caption": caption,
    }
    if reply_markup is not None:
        params["reply_markup"] = reply_markup
    if reply_keyboard_markup is not None:
        params["_reply_keyboard"] = reply_keyboard_markup
    return TelegramAction("sendPhoto", params)


def _edit(
    chat_id: int,
    message_id: int,
    text: str,
    reply_markup: dict[str, Any],
) -> TelegramAction:
    return TelegramAction(
        "editMessageText",
        {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "reply_markup": reply_markup,
        },
    )


async def _enqueue_actions(
    session: AsyncSession,
    *,
    update_id: int,
    user_id: uuid.UUID | None,
    actions: list[TelegramAction],
    now: datetime,
) -> None:
    expanded: list[TelegramAction] = []
    for action in actions:
        params = dict(action.params)
        reply_keyboard_markup = params.pop("_reply_keyboard", None)
        if reply_keyboard_markup is not None:
            if "reply_markup" not in params:
                params["reply_markup"] = reply_keyboard_markup
            else:
                expanded.append(
                    TelegramAction(
                        "sendMessage",
                        {
                            "chat_id": params["chat_id"],
                            "text": "Меню доступно внизу экрана.",
                            "reply_markup": reply_keyboard_markup,
                        },
                    )
                )
        expanded.append(TelegramAction(action.method, params))

    for index, action in enumerate(expanded):
        await session.execute(
            insert(OutboxEvent)
            .values(
                id=uuid.uuid4(),
                event_type="telegram.call",
                aggregate_type="telegram_user",
                aggregate_id=user_id,
                idempotency_key=f"telegram:update:{update_id}:action:{index}",
                payload_json={"method": action.method, "params": action.params},
                status=OutboxStatus.PENDING.value,
                attempts=0,
                available_at=now,
            )
            .on_conflict_do_nothing(index_elements=[OutboxEvent.idempotency_key])
        )


def _update_user(update: TelegramUpdateRequest):
    if update.message is not None:
        return update.message.from_user
    assert update.callback_query is not None
    return update.callback_query.from_user


def _is_pairing_start(update: TelegramUpdateRequest) -> bool:
    return bool(
        update.message is not None
        and update.message.text is not None
        and _PAIRING_START.fullmatch(update.message.text)
    )


def _remaining_days(now: datetime, expires_at: datetime) -> int:
    return max(1, math.ceil((expires_at - now).total_seconds() / 86_400))


def _chrome_url(settings: Settings) -> str:
    if settings.chrome_web_store_url is not None:
        return str(settings.chrome_web_store_url)
    return "https://chromewebstore.google.com/"


def _support_url(telegram_id: int, settings: Settings) -> str:
    username = settings.telegram_support_username or settings.telegram_bot_username or "telegram"
    return f"https://t.me/{username}?start=user_{telegram_id}"


def _legal_url(settings: Settings, document: str) -> str:
    assert settings.legal_documents_base_url is not None
    return f"{str(settings.legal_documents_base_url).rstrip('/')}/{document}"


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
