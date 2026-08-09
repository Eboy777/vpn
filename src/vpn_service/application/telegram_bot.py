from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.pairing import PairingService
from vpn_service.config import Settings, TariffSettings
from vpn_service.domain.enums import OutboxStatus, PaymentStatus, UserStatus
from vpn_service.http.schemas import TelegramCallbackQuery, TelegramMessage, TelegramUpdateRequest
from vpn_service.persistence.models import OutboxEvent, Payment, TelegramUpdateEvent, User
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
    expires_at: datetime | None
    remaining_days: int | None

    @property
    def has_access(self) -> bool:
        return self.expires_at is not None


class TelegramBotService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
        pairing_service: PairingService,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._pairing_service = pairing_service
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
            user, created = await self._lock_or_create_user(
                session,
                telegram_id=telegram_user.id,
                now=now,
            )
            actions = await self._actions_for_update(
                session,
                update=update,
                user=user,
                first_name=telegram_user.first_name,
                created=created,
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
        first_name: str,
        created: bool,
        now: datetime,
    ) -> list[TelegramAction]:
        profile = await self._profile(session, user, now)
        if update.message is not None:
            return self._message_actions(
                update.message,
                profile=profile,
                first_name=first_name,
                created=created,
            )
        assert update.callback_query is not None
        return self._callback_actions(update.callback_query, profile=profile)

    def _message_actions(
        self,
        message: TelegramMessage,
        *,
        profile: ProfileView,
        first_name: str,
        created: bool,
    ) -> list[TelegramAction]:
        text = (message.text or "").strip()
        if text.startswith("/start"):
            actions: list[TelegramAction] = []
            if created:
                actions.append(
                    _send(
                        message.chat.id,
                        f"Привет, {first_name}! Это {self._settings.vpn_brand_name} — "
                        "быстрый и безопасный доступ в интернет.",
                        reply_markup={
                            "inline_keyboard": [
                                [
                                    {
                                        "text": "📢 Наш канал",
                                        "url": self._channel_url(),
                                    }
                                ]
                            ]
                        },
                    )
                )
            actions.append(
                _send_profile(
                    message.chat.id,
                    profile,
                    self._settings,
                    ensure_reply_keyboard=True,
                )
            )
            return actions
        if text == "⚡ Подключить VPN":
            return [_send_connect_hub(message.chat.id, profile, self._settings)]
        if text == "💬 Поддержка":
            return [_send_support(message.chat.id, profile.telegram_id, self._settings)]
        return [_send_profile(message.chat.id, profile, self._settings)]

    def _callback_actions(
        self,
        callback: TelegramCallbackQuery,
        *,
        profile: ProfileView,
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
            actions.append(_edit_profile(chat_id, message_id, profile, self._settings))
        elif data == "menu:connect":
            actions.append(_edit_connect_hub(chat_id, message_id, profile, self._settings))
        elif data == "menu:tariffs":
            actions.append(_edit_tariffs(chat_id, message_id, self._settings))
        elif data == "support:list":
            actions.append(_edit_support(chat_id, message_id, profile.telegram_id, self._settings))
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
        elif data == "phone:setup" or data == "phone:retry":
            actions.append(_edit_phone_placeholder(chat_id, message_id))
        elif data.startswith("tariff:"):
            code = data.removeprefix("tariff:")
            actions.append(_edit_payment(chat_id, message_id, code, self._settings))
        elif data.startswith("payment:"):
            code = data.removeprefix("payment:")
            actions.append(_edit_payment_placeholder(chat_id, message_id, code, self._settings))
        else:
            actions.append(_edit_profile(chat_id, message_id, profile, self._settings))
        return actions

    async def _profile(
        self,
        session: AsyncSession,
        user: User,
        now: datetime,
    ) -> ProfileView:
        latest_paid_tariff = await session.scalar(
            select(Payment.tariff_code)
            .where(
                Payment.user_id == user.id,
                Payment.status == PaymentStatus.PAID.value,
            )
            .order_by(Payment.paid_at.desc(), Payment.created_at.desc())
            .limit(1)
        )
        if user.subscription_expires_at is not None and user.subscription_expires_at > now:
            expires_at = user.subscription_expires_at
            return ProfileView(
                telegram_id=user.telegram_id,
                tariff_name=tariff_name(latest_paid_tariff or "vpn_30d"),
                access_kind="paid",
                expires_at=expires_at,
                remaining_days=_remaining_days(now, expires_at),
            )
        if user.trial_expires_at is not None and user.trial_expires_at > now:
            expires_at = user.trial_expires_at
            return ProfileView(
                telegram_id=user.telegram_id,
                tariff_name="Пробный доступ",
                access_kind="trial",
                expires_at=expires_at,
                remaining_days=_remaining_days(now, expires_at),
            )
        return ProfileView(
            telegram_id=user.telegram_id,
            tariff_name=None,
            access_kind=None,
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

    def _channel_url(self) -> str:
        if self._settings.telegram_channel_url is not None:
            return str(self._settings.telegram_channel_url)
        return f"https://t.me/{self._settings.telegram_bot_username or 'telegram'}"


def reply_keyboard() -> dict[str, Any]:
    return {
        "keyboard": [
            [{"text": "⚡ Подключить VPN"}],
            [{"text": "👤 Мой профиль"}, {"text": "💬 Поддержка"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


def profile_text(profile: ProfileView) -> str:
    lines = ["👤 Мой профиль", f"🆔 ID: {profile.telegram_id}"]
    if not profile.has_access:
        lines.append("❌ Тариф: Подписка не активна")
        return "\n".join(lines)
    assert profile.tariff_name is not None
    assert profile.expires_at is not None
    assert profile.remaining_days is not None
    lines.extend(
        [
            f"🚀 Тариф: {profile.tariff_name} (Активен)",
            "📅 Действует до: "
            f"{profile.expires_at.astimezone(UTC).strftime('%d.%m.%Y')} "
            f"(осталось {profile.remaining_days} дн.)",
        ]
    )
    return "\n".join(lines)


def profile_keyboard(profile: ProfileView, settings: Settings) -> dict[str, Any]:
    if not profile.has_access:
        return {
            "inline_keyboard": [
                [{"text": "⚡ Купить подписку", "callback_data": "menu:tariffs"}]
            ]
        }
    return {
        "inline_keyboard": [
            [{"text": "📱 Настроить на телефоне", "callback_data": "phone:setup"}],
            [{"text": "🌐 Настроить в браузере", "url": _chrome_url(settings)}],
            [{"text": "⚙️ Продлить / Сменить тариф", "callback_data": "menu:tariffs"}],
        ]
    }


def tariff_name(code: str) -> str:
    return "Flow" if code == "vpn_30d" else code.replace("_", " ").title()


def tariff_price(tariff: TariffSettings) -> str:
    rubles, kopecks = divmod(tariff.amount_minor, 100)
    return f"{rubles} ₽" if kopecks == 0 else f"{rubles},{kopecks:02d} ₽"


def tariffs_text(settings: Settings) -> str:
    lines = ["Выберите подходящий тариф:"]
    for code, tariff in settings.tariffs_json.items():
        if tariff.enabled:
            lines.append(
                f"\n{tariff_name(code)} — {tariff.description}, {tariff_price(tariff)}."
            )
    return "".join(lines)


def tariffs_keyboard(settings: Settings) -> dict[str, Any]:
    rows = [
        [
            {
                "text": f"Тариф {tariff_name(code)} — {tariff_price(tariff)}",
                "callback_data": f"tariff:{code}",
            }
        ]
        for code, tariff in settings.tariffs_json.items()
        if tariff.enabled
    ]
    rows.append([{"text": "◀️ Назад", "callback_data": "menu:profile"}])
    return {"inline_keyboard": rows}


def support_text() -> str:
    return "Часто задаваемые вопросы:"


def support_keyboard(telegram_id: int, settings: Settings) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "❓ Не работает подключение", "callback_data": "faq:connect"}],
            [{"text": "❓ Как установить на iOS/Android?", "callback_data": "faq:mobile"}],
            [{"text": "❓ Оплата прошла, но подписки нет", "callback_data": "faq:payment"}],
            [{"text": "✍️ Написать в поддержку", "url": _support_url(telegram_id, settings)}],
        ]
    }


def _send_profile(
    chat_id: int,
    profile: ProfileView,
    settings: Settings,
    *,
    ensure_reply_keyboard: bool = False,
) -> TelegramAction:
    return _send(
        chat_id,
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


def _edit_faq(
    chat_id: int,
    message_id: int,
    topic: str,
    telegram_id: int,
    settings: Settings,
) -> TelegramAction:
    answers = {
        "connect": (
            "Проверьте, что подписка активна, и переподключите VPN. "
            "Если ошибка сохраняется, напишите в поддержку."
        ),
        "mobile": (
            "Сценарий настройки телефона подготовлен, но генерация VLESS-конфига "
            "через 3X-UI/Marzban пока работает как пустышка."
        ),
        "payment": (
            "Обновление подписки может занять до минуты после подтверждения оплаты. "
            "Если статус не изменился, отправьте в поддержку ID пользователя."
        ),
    }
    return _edit(
        chat_id,
        message_id,
        answers.get(topic, "Ответ пока не добавлен."),
        {
            "inline_keyboard": [
                [{"text": "◀️ К вопросам", "callback_data": "support:list"}],
                [{"text": "✍️ Написать в поддержку", "url": _support_url(telegram_id, settings)}],
            ]
        },
    )


def _edit_phone_placeholder(chat_id: int, message_id: int) -> TelegramAction:
    return _edit(
        chat_id,
        message_id,
        "Не удалось сгенерировать VLESS-конфиг. 3X-UI/Marzban пока не подключены. "
        "Попробуйте снова через 1 минуту.",
        {
            "inline_keyboard": [
                [{"text": "🔄 Повторить", "callback_data": "phone:retry"}],
                [{"text": "◀️ Назад", "callback_data": "menu:connect"}],
            ]
        },
    )


def _edit_tariffs(chat_id: int, message_id: int, settings: Settings) -> TelegramAction:
    return _edit(chat_id, message_id, tariffs_text(settings), tariffs_keyboard(settings))


def _edit_payment(
    chat_id: int,
    message_id: int,
    code: str,
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
    return _edit(
        chat_id,
        message_id,
        f"Выбран тариф: {tariff_name(code)} ({tariff_price(tariff)}). "
        "Нажмите кнопку ниже для оплаты:",
        {
            "inline_keyboard": [
                [{"text": "💳 Оплатить", "callback_data": f"payment:{code}"}],
                [{"text": "◀️ Назад", "callback_data": "menu:tariffs"}],
            ]
        },
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


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
