from __future__ import annotations

import hmac
import json
import logging

from fastapi import APIRouter, Request
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response

from vpn_service.application.telegram_bot import TelegramBotService
from vpn_service.http.schemas import TelegramUpdateRequest

router = APIRouter(prefix="/integrations/telegram", tags=["telegram"])
logger = logging.getLogger(__name__)
_NO_STORE = {"Cache-Control": "no-store"}


@router.post("/webhook/{path_secret}")
async def telegram_webhook(path_secret: str, request: Request) -> Response:
    settings = request.app.state.settings
    configured_path = settings.telegram_webhook_path_secret
    if configured_path is None or not hmac.compare_digest(
        path_secret,
        configured_path.get_secret_value(),
    ):
        return Response(status_code=404, headers=_NO_STORE)
    configured_header = settings.telegram_webhook_secret
    received_header = request.headers.get("x-telegram-bot-api-secret-token", "")
    if configured_header is None or not hmac.compare_digest(
        received_header,
        configured_header.get_secret_value(),
    ):
        return Response(status_code=401, headers=_NO_STORE)
    if request.query_params or "authorization" in request.headers or "cookie" in request.headers:
        return Response(status_code=400, headers=_NO_STORE)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return Response(status_code=400, headers=_NO_STORE)
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.telegram_update_max_body_bytes:
                return Response(status_code=413, headers=_NO_STORE)
        except ValueError:
            return Response(status_code=400, headers=_NO_STORE)
    body = await request.body()
    if len(body) > settings.telegram_update_max_body_bytes:
        return Response(status_code=413, headers=_NO_STORE)
    try:
        payload = TelegramUpdateRequest.model_validate(json.loads(body))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError):
        return Response(status_code=400, headers=_NO_STORE)

    service: TelegramBotService | None = request.app.state.telegram_bot_service
    if service is None:
        return Response(status_code=503, headers=_NO_STORE)
    try:
        await service.process_update(payload)
    except SQLAlchemyError:
        logger.exception("telegram_webhook_database_error")
        return Response(status_code=503, headers=_NO_STORE)
    except Exception:
        logger.exception("telegram_webhook_internal_error")
        return Response(status_code=500, headers=_NO_STORE)
    return Response(status_code=200, headers=_NO_STORE)
