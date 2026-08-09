from __future__ import annotations

from typing import Any

import httpx

from vpn_service.config import Settings

_ALLOWED_METHODS = {"answerCallbackQuery", "editMessageText", "sendMessage"}


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
        if method not in _ALLOWED_METHODS or not isinstance(params, dict):
            raise TelegramDeliveryError("invalid Telegram outbox payload")
        await self.call(method, params)

    async def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method not in _ALLOWED_METHODS:
            raise TelegramDeliveryError("unsupported Telegram Bot API method")
        if self._token is None:
            raise TelegramDeliveryError("Telegram bot token is not configured")

        url = f"{self._api_base_url}/bot{self._token}/{method}"
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(10.0),
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
        result = body.get("result")
        return result if isinstance(result, dict) else {}
