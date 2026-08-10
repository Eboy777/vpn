from __future__ import annotations

from fastapi import APIRouter, Request

from vpn_service.application.telemetry import TelemetryService
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.access import _authenticate
from vpn_service.http.client_ip import client_ip
from vpn_service.http.pairing import _require_json
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import (
    DeviceTelemetryRequest,
    ExtensionLifecycleRequest,
    TelemetryAcceptedResponse,
)

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])


@router.post("/lifecycle", response_model=TelemetryAcceptedResponse)
async def extension_lifecycle(
    request: Request,
    payload: ExtensionLifecycleRequest,
) -> ContractJSONResponse:
    _require_json(request)
    if request.query_params or "authorization" in request.headers:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    processed = await _service(request).record_lifecycle(
        payload,
        source_ip=_client_ip(request),
    )
    body = TelemetryAcceptedResponse(processed=processed)
    return ContractJSONResponse(content=body.model_dump(mode="json"), headers=no_store_headers())


@router.post("/events", response_model=TelemetryAcceptedResponse)
async def device_event(
    request: Request,
    payload: DeviceTelemetryRequest,
) -> ContractJSONResponse:
    _require_json(request)
    if request.query_params:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    processed = await _service(request).record_device_event(
        await _authenticate(request),
        payload,
        source_ip=_client_ip(request),
    )
    body = TelemetryAcceptedResponse(processed=processed)
    return ContractJSONResponse(content=body.model_dump(mode="json"), headers=no_store_headers())


def _service(request: Request) -> TelemetryService:
    service: TelemetryService | None = request.app.state.telemetry_service
    if service is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    return service


def _client_ip(request: Request) -> str:
    return client_ip(request, request.app.state.settings.trusted_proxy_cidrs)
