from __future__ import annotations

from fastapi import APIRouter, Request

from vpn_service.application.discovery import DiscoveryService
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import DiscoveryDocumentResponse

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.get("/control-ingresses", response_model=DiscoveryDocumentResponse)
async def control_ingresses(request: Request) -> ContractJSONResponse:
    if request.query_params or await request.body() or "authorization" in request.headers:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    service: DiscoveryService | None = request.app.state.discovery_service
    if service is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    body = await service.signed_document()
    DiscoveryDocumentResponse.model_validate(body)
    return ContractJSONResponse(content=body, headers=no_store_headers())
