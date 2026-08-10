from __future__ import annotations

from typing import Any

from vpn_service.config import Settings
from vpn_service.external.telegram import TelegramBotClient, TelegramDeliveryError


class AdminTelegramNotifier:
    def __init__(self, settings: Settings) -> None:
        self._chat_ids = tuple(settings.admin_telegram_chat_ids_json)
        self._client = TelegramBotClient(settings, token=settings.admin_telegram_bot_token)

    async def handle_outbox(self, payload: dict[str, Any]) -> None:
        if not self._chat_ids:
            raise TelegramDeliveryError("admin Telegram recipients are not configured")
        text = _render_alert(payload)
        for chat_id in self._chat_ids:
            await self._client.call(
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": text,
                    "disable_web_page_preview": True,
                },
            )


def _render_alert(payload: dict[str, Any]) -> str:
    event = payload.get("event")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise TelegramDeliveryError("invalid admin alert payload")
    if event == "node_blocked":
        return (
            "🚨 Нода заблокирована\n\n"
            f"Нода: {_safe(data.get('node_name'))}\n"
            f"ID: {_safe(data.get('node_id'))}\n"
            f"Причина: {_safe(data.get('reason'))}"
        )
    if event == "node_recovery_ready":
        return (
            "✅ Нода готова к ручному восстановлению\n\n"
            f"Нода: {_safe(data.get('node_name'))}\n"
            f"ID: {_safe(data.get('node_id'))}"
        )
    if event == "capacity_exhausted":
        return (
            "⚠️ Недостаточно свободных VPN-нод\n\n"
            f"Перенесено: {_safe(data.get('reassigned_users'))}\n"
            f"Без доступной ноды: {_safe(data.get('users_without_capacity'))}"
        )
    if event == "node_health_warning":
        return (
            "⚠️ Проблема со здоровьем ноды\n\n"
            f"Нода: {_safe(data.get('node_name'))}\n"
            f"ID: {_safe(data.get('node_id'))}\n"
            f"Проблема: {_safe(data.get('problem'))}\n"
            f"Значение: {_safe(data.get('value'))}"
        )
    if event == "control_ingress_failed":
        return (
            "🚨 Входной прокси backend недоступен из России\n\n"
            f"Адрес: {_safe(data.get('url'))}\n"
            f"Ошибка: {_safe(data.get('error_code'))}\n"
            f"Проверок подряд: {_safe(data.get('attempts'))}"
        )
    if event == "control_ingress_recovered":
        return (
            "✅ Входной прокси backend снова доступен из России\n\n"
            f"Адрес: {_safe(data.get('url'))}"
        )
    raise TelegramDeliveryError("unsupported admin alert type")


def _safe(value: object) -> str:
    rendered = str(value)
    return rendered[:256].replace("\n", " ").replace("\r", " ")
