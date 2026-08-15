from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
import pytest

from vpn_service.app import create_app
from vpn_service.application.telegram_bot import (
    DeviceView,
    ProfileView,
    TelegramBotService,
    _edit_device_confirmation,
    _edit_devices,
    _edit_faq,
    _edit_payment,
    _is_pairing_start,
    _phone_placeholder_text,
    _send_connect_hub,
    _send_profile,
    profile_keyboard,
    profile_text,
    reply_keyboard,
    support_text,
    tariff_price,
    tariffs_keyboard,
    tariffs_text,
    welcome_text,
)
from vpn_service.config import Settings
from vpn_service.external.telegram import TelegramBotClient, TelegramDeliveryError
from vpn_service.http.schemas import TelegramUpdateRequest
from vpn_service.worker.telegram_polling import TelegramPollingWorker


def test_bot_copy_and_keyboards_follow_the_approved_scenarios(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    guest = ProfileView(
        telegram_id=123456789,
        tariff_name=None,
        access_kind=None,
        started_at=None,
        expires_at=None,
        remaining_days=None,
    )
    started_at = datetime(2026, 8, 10, tzinfo=UTC)
    expires_at = datetime(2026, 9, 9, tzinfo=UTC)
    active = ProfileView(
        telegram_id=123456789,
        tariff_name="Virgo FLOW",
        access_kind="paid",
        started_at=started_at,
        expires_at=expires_at,
        remaining_days=30,
    )

    assert profile_text(guest) == (
        "👤 Мой профиль\n\n"
        "├ ‣ ID: 123456789\n"
        "└ ‣ Тариф: Подписка не активна\n\n"
        "Выберите тарифный план, чтобы оформить доступ!"
    )
    assert "Тариф: Virgo FLOW" in profile_text(active)
    assert "Дата начала: 10.08.2026" in profile_text(active)
    assert "09.09.2026" in profile_text(active)
    assert profile_keyboard(guest, settings)["inline_keyboard"][0][0]["callback_data"] == (
        "menu:tariffs"
    )
    assert profile_keyboard(guest, settings)["inline_keyboard"][1][0]["callback_data"] == (
        "devices:list"
    )
    assert profile_keyboard(active, settings)["inline_keyboard"][0][0]["callback_data"] == (
        "phone:setup"
    )
    assert reply_keyboard()["keyboard"] == [
        [{"text": "⚡️ Подключить VPN"}],
        [{"text": "👤 Мой профиль"}, {"text": "💬 Поддержка"}],
    ]
    assert "Virgo FLOW" in tariffs_text(settings)
    assert "3 месяца — 499 ₽" in tariffs_text(settings)
    assert "Virgo SPACE — рекомендуем" in tariffs_text(settings)
    assert "6 месяцев — 1 499 ₽" in tariffs_text(settings)
    assert "Тестовый тариф Lava" in tariffs_text(settings)
    assert tariff_price(settings.tariffs_json["flow_1m"]) == "299 ₽"
    assert tariff_price(settings.tariffs_json["space_6m"]) == "1 499 ₽"
    assert len(tariffs_keyboard(settings)["inline_keyboard"]) == 8
    assert tariffs_keyboard(settings)["inline_keyboard"][-1][0]["callback_data"] == ("menu:profile")
    assert welcome_text(settings).startswith("Привет! 🛰\n\nДобро пожаловать в Virgo VPN")
    assert "Служба поддержки Virgo VPN" in support_text()
    assert "VLESS" not in _phone_placeholder_text()
    assert "Marzban" not in _phone_placeholder_text()

    profile_action = _send_profile(123456789, guest, settings)
    assert profile_action.method == "sendPhoto"
    assert profile_action.params["photo_asset"] == "profile"
    assert profile_action.params["caption"] == profile_text(guest)

    connect_action = _send_connect_hub(123456789, guest, settings)
    assert connect_action.method == "sendPhoto"
    assert connect_action.params["photo_asset"] == "welcome"
    assert connect_action.params["caption"] == (
        "У вас нет активной подписки. Подключите тариф для доступа к VPN:"
    )

    payment_action = _edit_payment(
        123456789,
        7,
        "flow_1m",
        guest,
        started_at,
        settings,
    )
    assert "Virgo FLOW · 1 месяц на 30 дней" in payment_action.params["text"]
    assert "09.09.2026" in payment_action.params["text"]
    assert "разовая оплата без автоматического продления" in payment_action.params["text"]

    browser_faq = _edit_faq(123456789, 7, "browser", 123456789, settings)
    assert "вход через Telegram" in browser_faq.params["text"]
    assert "ID из профиля" not in browser_faq.params["text"]


def test_device_management_requires_confirmation_and_uses_opaque_row_id() -> None:
    device_id = uuid.UUID("00000000-0000-4000-8000-000000000123")
    device = DeviceView(
        id=device_id,
        last_seen_at=datetime(2026, 8, 15, 10, 30, tzinfo=UTC),
        created_at=datetime(2026, 8, 10, 10, 30, tzinfo=UTC),
    )

    listing = _edit_devices(123456789, 7, [device])
    button = listing.params["reply_markup"]["inline_keyboard"][0][0]
    assert "Последняя активность: 15.08.2026 10:30 UTC" in listing.params["text"]
    assert button["callback_data"] == f"device:select:{device_id}"

    confirmation = _edit_device_confirmation(123456789, 7, device)
    confirm_button = confirmation.params["reply_markup"]["inline_keyboard"][0][0]
    assert "Если это текущее устройство" in confirmation.params["text"]
    assert confirm_button["callback_data"] == f"device:revoke:{device_id}"


@pytest.mark.asyncio
async def test_telegram_client_sends_only_allowlisted_methods(
    settings_factory: Callable[..., Settings],
) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})

    client = TelegramBotClient(
        settings_factory(),
        transport=httpx.MockTransport(handler),
        api_base_url="https://telegram.example.test",
    )
    result = await client.call("sendMessage", {"chat_id": 1, "text": "hello"})

    assert result == {"message_id": 7}
    assert requests[0].url.path.endswith("/sendMessage")
    assert requests[0].headers["content-type"] == "application/json"
    with pytest.raises(TelegramDeliveryError, match="unsupported"):
        await client.call("getUpdates", {})


@pytest.mark.asyncio
async def test_telegram_client_uploads_allowlisted_photo_asset(
    settings_factory: Callable[..., Settings],
) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 8}})

    client = TelegramBotClient(
        settings_factory(),
        transport=httpx.MockTransport(handler),
        api_base_url="https://telegram.example.test",
    )
    result = await client.call(
        "sendPhoto",
        {
            "chat_id": 1,
            "photo_asset": "profile",
            "caption": "👤 Мой профиль",
            "reply_markup": {"inline_keyboard": []},
        },
    )

    assert result == {"message_id": 8}
    assert requests[0].url.path.endswith("/sendPhoto")
    assert requests[0].headers["content-type"].startswith("multipart/form-data;")
    assert b"profile.png" in requests[0].content
    assert b"image/png" in requests[0].content
    assert b"\x89PNG\r\n\x1a\n" in requests[0].content

    with pytest.raises(TelegramDeliveryError, match="photo asset"):
        await client.call(
            "sendPhoto",
            {"chat_id": 1, "photo_asset": "../../secret", "caption": "bad"},
        )


@pytest.mark.asyncio
async def test_telegram_client_prepares_and_reads_long_polling_updates(
    settings_factory: Callable[..., Settings],
) -> None:
    methods: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        methods.append(method)
        result = [] if method == "getUpdates" else True
        return httpx.Response(200, json={"ok": True, "result": result})

    client = TelegramBotClient(
        settings_factory(),
        transport=httpx.MockTransport(handler),
        api_base_url="https://telegram.example.test",
    )

    await client.prepare_polling()
    updates = await client.get_updates(offset=42, timeout_seconds=1)

    assert updates == []
    assert methods == ["deleteWebhook", "getUpdates"]


class _FakeTelegramBotService:
    def __init__(self) -> None:
        self.updates = []

    async def process_update(self, update):
        self.updates.append(update)
        return "processed"


@pytest.mark.asyncio
async def test_polling_worker_processes_supported_updates_and_skips_poison_update() -> None:
    service = _FakeTelegramBotService()
    worker = TelegramPollingWorker(service, object())  # type: ignore[arg-type]
    valid = {
        "update_id": 10,
        "message": {
            "message_id": 10,
            "date": 1_786_000_000,
            "from": {"id": 7, "is_bot": False, "first_name": "Test"},
            "chat": {"id": 7, "type": "private"},
            "text": "/start",
        },
    }

    offset = await worker._process_batch(  # noqa: SLF001
        [valid, {"update_id": 11, "channel_post": {}}],
        offset=None,
    )

    assert offset == 12
    assert [update.update_id for update in service.updates] == [10]


@pytest.mark.asyncio
async def test_webhook_accepts_message_and_callback_updates(
    settings_factory: Callable[..., Settings],
) -> None:
    async def probe() -> bool:
        return True

    settings = settings_factory()
    app = create_app(settings, database_probe=probe)
    service = _FakeTelegramBotService()
    app.state.telegram_bot_service = service
    path = (
        "/integrations/telegram/webhook/" + settings.telegram_webhook_path_secret.get_secret_value()  # type: ignore[union-attr]
    )
    headers = {
        "X-Telegram-Bot-Api-Secret-Token": (
            settings.telegram_webhook_secret.get_secret_value()  # type: ignore[union-attr]
        )
    }
    user = {"id": 123456789, "is_bot": False, "first_name": "Test"}
    message = {
        "message_id": 10,
        "date": 1_786_000_000,
        "from": user,
        "chat": {"id": 123456789, "type": "private"},
        "text": "👤 Мой профиль",
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        message_response = await client.post(
            path,
            headers=headers,
            json={"update_id": 1, "message": message},
        )
        callback_response = await client.post(
            path,
            headers=headers,
            json={
                "update_id": 2,
                "callback_query": {
                    "id": "callback-1",
                    "from": user,
                    "message": {
                        **message,
                        "from": {
                            "id": 999,
                            "is_bot": True,
                            "first_name": "Virgo",
                        },
                    },
                    "data": "menu:tariffs",
                },
            },
        )

    assert message_response.status_code == 200
    assert callback_response.status_code == 200
    assert service.updates[0].message.text == "👤 Мой профиль"
    assert service.updates[1].callback_query.data == "menu:tariffs"


def test_pairing_start_detection_requires_separate_43_character_token() -> None:
    update = TelegramUpdateRequest.model_validate(
        {
            "update_id": 1,
            "message": {
                "message_id": 1,
                "date": 1_786_000_000,
                "from": {"id": 7, "is_bot": False, "first_name": "Test"},
                "chat": {"id": 7, "type": "private"},
                "text": f"/start {'a' * 43}",
                "entities": [{"type": "bot_command", "offset": 0, "length": 6}],
            },
        }
    )

    assert TelegramBotService is not None
    assert _is_pairing_start(update)


def test_support_deep_link_opens_support_section(
    settings_factory: Callable[..., Settings],
) -> None:
    service = TelegramBotService.__new__(TelegramBotService)
    service._settings = settings_factory()  # noqa: SLF001
    profile = ProfileView(123456789, None, None, None, None, None)
    message = TelegramUpdateRequest.model_validate(
        {
            "update_id": 2,
            "message": {
                "message_id": 2,
                "date": 1_786_000_000,
                "from": {"id": 123456789, "is_bot": False, "first_name": "Test"},
                "chat": {"id": 123456789, "type": "private"},
                "text": "/start support",
            },
        }
    ).message
    assert message is not None

    action = service._message_actions(message, profile=profile)[0]  # noqa: SLF001

    assert action.method == "sendMessage"
    assert "Служба поддержки Virgo VPN" in action.params["text"]
