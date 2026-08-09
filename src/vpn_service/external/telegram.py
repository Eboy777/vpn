from __future__ import annotations

from typing import Any

import httpx

from vpn_service.config import Settings

_OUTBOX_METHODS = {"answerCallbackQuery", "editMessageText", "sendMessage"}


class TelegramDeliveryError(RuntimeError):
    pass


class TelegramBotClient:
    """Small Telegram Bot API adapter used only by the durable outbox worker."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        api_base_url: str = "https://api.telegram.org",
    ) -> None:
        token = settings.telegram_bot_token
        self._token = token.get_secret_value() if token is not None else None
        self._transport = transport
        self._api_base_url = api_base_url.rstrip("/")

    async def handle_outbox(self, payload: dict[str, Any]) -> None:
        method = payload.get("method")
        params = payload.get("params")
        if method not in _OUTBOX_METHODS or not isinstance(params, dict):
            raise TelegramDeliveryError("invalid Telegram outbox payload")
        await self.call(method, params)

    async def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method not in _OUTBOX_METHODS:
            raise TelegramDeliveryError("unsupported Telegram Bot API method")
        result = await self._request(method, params, timeout_seconds=10.0)
        return result if isinstance(result, dict) else {}

    async def prepare_polling(self) -> None:
        await self._request(
            "deleteWebhook",
            {"drop_pending_updates": False},
            timeout_seconds=10.0,
        )

    async def get_updates(
        self,
        *,
        offset: int | None,
        timeout_seconds: int = 25,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "timeout": timeout_seconds,
            "allowed_updates": ["message", "callback_query"],
        }
        if offset is not None:
            params["offset"] = offset
        result = await self._request(
            "getUpdates",
            params,
            timeout_seconds=timeout_seconds + 10.0,
        )
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise TelegramDeliveryError("Telegram Bot API returned invalid updates")
        return result

    async def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout_seconds: float,
    ) -> Any:
        if self._token is None:
            raise TelegramDeliveryError("Telegram bot token is not configured")

        url = f"{self._api_base_url}/bot{self._token}/{method}"
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(timeout_seconds),
            ) as client:
                response = await client.post(url, json=params)
        except httpx.HTTPError as exc:
            raise TelegramDeliveryError("Telegram Bot API request failed") from exc
        if response.status_code != 200:
            raise TelegramDeliveryError(
                f"Telegram Bot API returned HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise TelegramDeliveryError("Telegram Bot API returned invalid JSON") from exc
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise TelegramDeliveryError("Telegram Bot API rejected the request")
        return body.get("result")
