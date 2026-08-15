from __future__ import annotations

import hmac
import json
import re

from fastapi import APIRouter, Request
from pydantic import ValidationError
from starlette.responses import Response

from vpn_service.application.payments import PaymentService
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.access import _authenticate
from vpn_service.http.pairing import _require_json
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import (
    LavaWebhookRequest,
    LavaWebhookResponse,
    PaymentCreateRequest,
    PaymentCreateResponse,
    SubscriptionCancelResponse,
)

router = APIRouter(prefix="/api/payments", tags=["payments"])
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_.:-]{16,128}$")


@router.post("/create", response_model=PaymentCreateResponse)
async def create_payment(
    request: Request,
    payload: PaymentCreateRequest,
) -> ContractJSONResponse:
    _require_json(request)
    if request.query_params:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    idempotency_key = request.headers.get("idempotency-key", "")
    if _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        raise ApplicationError(
            400,
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key is invalid",
        )
    device = await _authenticate(request)
    result = await _service(request).create(
        user_id=device.user_id,
        tariff_code=payload.tariff_code,
        idempotency_key=idempotency_key,
        email=payload.email,
        terms_accepted=payload.terms_accepted,
        recurring_consent=payload.recurring_consent,
    )
    body = PaymentCreateResponse(
        payment_id=result.payment_id,
        contract_id=result.contract_id,
        payment_url=result.payment_url,
        tariff_code=result.tariff_code,
        amount_minor=result.amount_minor,
        currency=result.currency,
        periodicity=result.periodicity,
    )
    return ContractJSONResponse(
        status_code=200 if result.replayed else 201,
        content=body.model_dump(mode="json"),
        headers=no_store_headers(),
    )


@router.post("/subscription/cancel", response_model=SubscriptionCancelResponse)
async def cancel_subscription(request: Request) -> ContractJSONResponse:
    if request.query_params or await request.body() or "content-type" in request.headers:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    device = await _authenticate(request)
    cancelled = await _service(request).cancel(user_id=device.user_id)
    return ContractJSONResponse(
        content=SubscriptionCancelResponse(cancelled=cancelled).model_dump(mode="json"),
        headers=no_store_headers(),
    )


@router.post("/lava/webhook/payment", response_model=LavaWebhookResponse)
@router.post("/lava/webhook/recurring", response_model=LavaWebhookResponse)
async def lava_webhook(request: Request) -> ContractJSONResponse | Response:
    settings = request.app.state.settings
    expected = settings.lava_webhook_api_key
    received = request.headers.get("x-api-key", "")
    if expected is None or not hmac.compare_digest(received, expected.get_secret_value()):
        return Response(status_code=401, headers=no_store_headers())
    if request.query_params or "authorization" in request.headers or "cookie" in request.headers:
        return Response(status_code=400, headers=no_store_headers())
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return Response(status_code=415, headers=no_store_headers())
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.lava_webhook_max_body_bytes:
                return Response(status_code=413, headers=no_store_headers())
        except ValueError:
            return Response(status_code=400, headers=no_store_headers())
    body = await request.body()
    if len(body) > settings.lava_webhook_max_body_bytes:
        return Response(status_code=413, headers=no_store_headers())
    try:
        payload = LavaWebhookRequest.model_validate(json.loads(body))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError):
        return Response(status_code=400, headers=no_store_headers())
    result = await _service(request).handle_webhook(payload=payload, raw_body=body)
    response = LavaWebhookResponse(result=result.result)
    return ContractJSONResponse(
        content=response.model_dump(mode="json"),
        headers=no_store_headers(),
    )


def _service(request: Request) -> PaymentService:
    service: PaymentService | None = request.app.state.payment_service
    if service is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    return service
