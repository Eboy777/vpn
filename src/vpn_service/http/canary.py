from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Request

from vpn_service.application.canary import CanaryAuthenticator, CanaryReportService
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.pairing import _require_json
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import CanaryRunRequest, CanaryRunResponse

router = APIRouter(prefix="/internal/canaries", tags=["canary"])
_BEARER = re.compile(r"^Bearer ([A-Za-z0-9_-]{43})$")


@router.post("/{canary_id}/checks", response_model=CanaryRunResponse)
async def canary_checks(
    request: Request,
    canary_id: str,
    payload: CanaryRunRequest,
) -> ContractJSONResponse:
    _require_json(request)
    if request.query_params:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    try:
        parsed_canary_id = uuid.UUID(canary_id)
    except ValueError as exc:
        raise ApplicationError(400, "INVALID_CANARY_ID", "Canary ID is invalid") from exc
    if str(parsed_canary_id) != canary_id:
        raise ApplicationError(400, "INVALID_CANARY_ID", "Canary ID is invalid")
    match = _BEARER.fullmatch(request.headers.get("authorization", ""))
    if match is None:
        raise ApplicationError(
            401,
            "INVALID_CANARY_TOKEN",
            "Canary token is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    authenticator: CanaryAuthenticator | None = request.app.state.canary_authenticator
    service: CanaryReportService | None = request.app.state.canary_report_service
    if authenticator is None or service is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    response = await service.process(
        await authenticator.authenticate(match.group(1)),
        requested_canary_id=parsed_canary_id,
        payload=payload,
    )
    CanaryRunResponse.model_validate(response)
    return ContractJSONResponse(content=response, headers=no_store_headers())
