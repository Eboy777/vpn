from __future__ import annotations

import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Request

from vpn_service.application.access import AccessResult, AccessService, AccessState, PublicNode
from vpn_service.application.device_auth import AuthenticatedDevice, DeviceAuthenticator
from vpn_service.application.discovery import DiscoveryService
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.client_ip import client_ip
from vpn_service.http.pairing import _require_json
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import (
    AccessDetailsResponse,
    NodeListResponse,
    NodeSelectionResponse,
    NodeSelectRequest,
    ProxyCredentialsResponse,
    PublicNodeResponse,
    SelectableNodeResponse,
    StatusResponse,
    VpnStatusResponse,
)

router = APIRouter(prefix="/api", tags=["access"])
_BEARER = re.compile(r"^Bearer ([A-Za-z0-9_-]{43})$")


@router.get("/status", response_model=StatusResponse)
async def status(request: Request) -> ContractJSONResponse:
    await _validate_empty_get(request)
    result = await _service(request).status(await _authenticate(request))
    unavailable_reason = _unavailable_reason(result)
    node = _node_response(result.node)
    credentials = (
        ProxyCredentialsResponse(
            proxy_username=result.proxy_username,
            proxy_password=result.proxy_password,
        )
        if result.proxy_username is not None and result.proxy_password is not None
        else None
    )
    body = StatusResponse(
        device_id=result.device_id,
        account_id=result.account_id,
        access=AccessDetailsResponse(
            state=result.state.value,
            trial_expires_at=result.trial_expires_at,
            subscription_expires_at=result.subscription_expires_at,
            access_expires_at=result.access_expires_at,
            can_select_node=result.state == AccessState.PAID,
        ),
        node_selection_mode=result.node_selection_mode,
        vpn=VpnStatusResponse(
            available=node is not None,
            unavailable_reason=unavailable_reason,
            node=node,
            credentials=credentials,
            bypass_list=await _bypass_list(request),
        ),
        server_time=result.server_time,
        next_check_seconds=60,
    )
    return ContractJSONResponse(content=body.model_dump(mode="json"), headers=no_store_headers())


@router.get("/nodes", response_model=NodeListResponse)
async def nodes(request: Request) -> ContractJSONResponse:
    await _validate_empty_get(request)
    result = await _service(request).nodes(await _authenticate(request))
    body = NodeListResponse(
        nodes=[
            SelectableNodeResponse(
                id=node.id,
                name=node.name,
                country_code=node.country_code,
                selected=node.selected,
            )
            for node in result.nodes
        ],
        node_selection_mode=result.node_selection_mode,
        generated_at=result.generated_at,
    )
    return ContractJSONResponse(content=body.model_dump(mode="json"), headers=no_store_headers())


@router.post("/nodes/select", response_model=NodeSelectionResponse)
async def select_node(
    request: Request,
    payload: NodeSelectRequest,
) -> ContractJSONResponse:
    _require_json(request)
    if request.query_params:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    result = await _service(request).select_node(
        await _authenticate(request),
        payload.node_id,
        source_ip=client_ip(request, request.app.state.settings.trusted_proxy_cidrs),
    )
    body = NodeSelectionResponse(
        assigned_node=_node_response(result.assigned_node),
        node_selection_mode=result.node_selection_mode,
        changed=result.changed,
    )
    return ContractJSONResponse(content=body.model_dump(mode="json"), headers=no_store_headers())


async def _authenticate(request: Request) -> AuthenticatedDevice:
    match = _BEARER.fullmatch(request.headers.get("authorization", ""))
    if match is None:
        raise ApplicationError(
            401,
            "INVALID_DEVICE_TOKEN",
            "Device token is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    authenticator: DeviceAuthenticator | None = request.app.state.device_authenticator
    if authenticator is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    return await authenticator.authenticate(
        match.group(1),
        source_ip=client_ip(request, request.app.state.settings.trusted_proxy_cidrs),
    )


async def _validate_empty_get(request: Request) -> None:
    if request.query_params or await request.body() or "content-type" in request.headers:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")


def _service(request: Request) -> AccessService:
    service: AccessService | None = request.app.state.access_service
    if service is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    return service


def _node_response(node: PublicNode | None) -> PublicNodeResponse | None:
    if node is None:
        return None
    return PublicNodeResponse(
        id=node.id,
        name=node.name,
        host=node.host,
        port=node.port,
        country_code=node.country_code,
    )


def _unavailable_reason(result: AccessResult) -> str | None:
    if result.node is not None:
        return None
    if result.state == AccessState.BLOCKED:
        return "USER_BLOCKED"
    if result.state == AccessState.EXPIRED:
        return "ACCESS_EXPIRED"
    return "NO_ACTIVE_NODE"


async def _bypass_list(request: Request) -> list[str]:
    service: DiscoveryService | None = request.app.state.discovery_service
    urls = (
        await service.active_urls()
        if service is not None
        else [str(url).rstrip("/") for url in request.app.state.settings.public_control_urls_json]
    )
    return [urlsplit(url).hostname for url in urls if urlsplit(url).hostname is not None]
