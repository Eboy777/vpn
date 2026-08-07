from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Request

from vpn_service.application.pairing import (
    PairingPairedResult,
    PairingPendingResult,
    PairingService,
)
from vpn_service.domain.errors import ApplicationError, ErrorDetail
from vpn_service.http.client_ip import client_ip
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import (
    PairingInitRequest,
    PairingInitResponse,
    PairingPairedResponse,
    PairingPendingResponse,
)

router = APIRouter(prefix="/api/pairing", tags=["pairing"])
_BEARER = re.compile(r"^Bearer ([A-Za-z0-9_-]{43})$")


@router.post("/init", response_model=PairingInitResponse)
async def pairing_init(request: Request, payload: PairingInitRequest) -> ContractJSONResponse:
    _require_json(request)
    if request.query_params or "authorization" in request.headers:
        raise ApplicationError(
            400,
            "INVALID_REQUEST",
            "Request validation failed",
            details=(ErrorDetail(field=None, reason="unexpected_request_component"),),
        )
    service = _service(request)
    result = await service.initialize(
        payload.device_id,
        client_ip(request, request.app.state.settings.trusted_proxy_cidrs),
    )
    body = PairingInitResponse(
        device_id=result.device_id,
        pairing_session_token=result.pairing_session_token,
        telegram_url=result.telegram_url,
        expires_at=result.expires_at,
        poll_after_seconds=result.poll_after_seconds,
    )
    return ContractJSONResponse(
        status_code=201 if result.created else 200,
        content=body.model_dump(mode="json"),
        headers=no_store_headers(),
    )


@router.get("/status", response_model=PairingPendingResponse | PairingPairedResponse)
async def pairing_status(request: Request) -> ContractJSONResponse:
    if await request.body() or "content-type" in request.headers:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    query_items = request.query_params.multi_items()
    if len(query_items) != 1 or query_items[0][0] != "device_id":
        raise ApplicationError(
            400,
            "INVALID_REQUEST",
            "Request validation failed",
            details=(ErrorDetail(field="query.device_id", reason="required_single_value"),),
        )
    try:
        device_id = uuid.UUID(query_items[0][1])
    except ValueError as exc:
        raise ApplicationError(
            400,
            "INVALID_REQUEST",
            "Request validation failed",
            details=(ErrorDetail(field="query.device_id", reason="invalid_uuid"),),
        ) from exc
    if str(device_id) != query_items[0][1]:
        raise ApplicationError(
            400,
            "INVALID_REQUEST",
            "Request validation failed",
            details=(ErrorDetail(field="query.device_id", reason="invalid_uuid"),),
        )
    match = _BEARER.fullmatch(request.headers.get("authorization", ""))
    if match is None:
        raise ApplicationError(
            401,
            "INVALID_PAIRING_SESSION_TOKEN",
            "Pairing session token is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    result = await _service(request).status(
        device_id=device_id,
        pairing_session_token=match.group(1),
    )
    if isinstance(result, PairingPendingResult):
        body = PairingPendingResponse(
            expires_at=result.expires_at,
            poll_after_seconds=result.poll_after_seconds,
        )
        return ContractJSONResponse(
            status_code=202,
            content=body.model_dump(mode="json"),
            headers=no_store_headers({"Retry-After": str(result.poll_after_seconds)}),
        )
    assert isinstance(result, PairingPairedResult)
    body = PairingPairedResponse(device_id=result.device_id, device_token=result.device_token)
    return ContractJSONResponse(
        status_code=200,
        content=body.model_dump(mode="json"),
        headers=no_store_headers(),
    )


def _require_json(request: Request) -> None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ApplicationError(
            415,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
        )


def _service(request: Request) -> PairingService:
    service: PairingService | None = request.app.state.pairing_service
    if service is None:
        raise ApplicationError(503, "PAIRING_UNAVAILABLE", "Pairing is unavailable")
    return service
