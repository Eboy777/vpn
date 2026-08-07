from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Request, Response

from vpn_service.application.node_credentials import (
    AuthenticatedNode,
    NodeAuthenticator,
    NodeCredentialsService,
)
from vpn_service.domain.errors import ApplicationError, ErrorDetail
from vpn_service.http.pairing import _require_json
from vpn_service.http.responses import ContractJSONResponse, no_store_headers
from vpn_service.http.schemas import (
    NodeCredentialsAckRequest,
    NodeCredentialsAckResponse,
    NodeCredentialsSnapshotResponse,
)

router = APIRouter(prefix="/internal/nodes", tags=["node-credentials"])
_BEARER = re.compile(r"^Bearer ([A-Za-z0-9_-]{43})$")
_ETAG = re.compile(r'^"sha256:[0-9a-f]{64}"$')


@router.get("/{node_id}/credentials", response_model=NodeCredentialsSnapshotResponse)
async def credentials_snapshot(request: Request, node_id: str) -> Response:
    parsed_node_id = _canonical_node_id(node_id)
    if request.query_params or await request.body() or "content-type" in request.headers:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    if_none_match = request.headers.get("if-none-match")
    if if_none_match is not None and _ETAG.fullmatch(if_none_match) is None:
        raise ApplicationError(
            400,
            "INVALID_REQUEST",
            "Request validation failed",
            details=(ErrorDetail(field="header.If-None-Match", reason="invalid_etag"),),
        )
    result = await _service(request).snapshot(
        await _authenticate(request),
        requested_node_id=parsed_node_id,
        if_none_match=if_none_match,
    )
    headers = no_store_headers(
        {
            "ETag": f'"sha256:{result.revision}"',
            "X-Snapshot-Generated-At": result.generated_at,
            "X-Snapshot-Valid-Until": result.snapshot_valid_until,
        }
    )
    if result.not_modified:
        return Response(status_code=304, headers=headers)
    body = {
        "node_id": str(result.node_id),
        "node_status": result.node_status,
        "generated_at": result.generated_at,
        "snapshot_valid_until": result.snapshot_valid_until,
        "revision": result.revision,
        "credentials": [
            {
                "proxy_username": item.proxy_username,
                "proxy_password": item.proxy_password,
                "valid_until": item.valid_until,
            }
            for item in result.credentials
        ],
    }
    NodeCredentialsSnapshotResponse.model_validate(body)
    return ContractJSONResponse(content=body, headers=headers)


@router.post("/{node_id}/credentials/ack", response_model=NodeCredentialsAckResponse)
async def credentials_ack(
    request: Request,
    node_id: str,
    payload: NodeCredentialsAckRequest,
) -> ContractJSONResponse:
    parsed_node_id = _canonical_node_id(node_id)
    _require_json(request)
    if request.query_params:
        raise ApplicationError(400, "INVALID_REQUEST", "Request validation failed")
    result = await _service(request).acknowledge(
        await _authenticate(request),
        requested_node_id=parsed_node_id,
        revision=payload.revision,
    )
    NodeCredentialsAckResponse.model_validate(result.response)
    return ContractJSONResponse(content=result.response, headers=no_store_headers())


async def _authenticate(request: Request) -> AuthenticatedNode:
    match = _BEARER.fullmatch(request.headers.get("authorization", ""))
    if match is None:
        raise ApplicationError(
            401,
            "INVALID_NODE_TOKEN",
            "Node token is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    authenticator: NodeAuthenticator | None = request.app.state.node_authenticator
    if authenticator is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    return await authenticator.authenticate(match.group(1))


def _canonical_node_id(raw: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(raw)
    except ValueError as exc:
        raise ApplicationError(400, "INVALID_NODE_ID", "Node ID is invalid") from exc
    if str(parsed) != raw:
        raise ApplicationError(400, "INVALID_NODE_ID", "Node ID is invalid")
    return parsed


def _service(request: Request) -> NodeCredentialsService:
    service: NodeCredentialsService | None = request.app.state.node_credentials_service
    if service is None:
        raise ApplicationError(503, "SERVICE_UNAVAILABLE", "Service is unavailable")
    return service
