from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import logging
import secrets
import time
import uuid
from importlib.resources import files
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from vpn_service.admin_cli import (
    _activate_node,
    _add_node,
    _finalize_node_drain,
    _issue_node_token,
    _prepare_node_drain,
    _promote_node_token,
    _revoke_node_token,
)
from vpn_service.application.admin_alerts import enqueue_admin_alert
from vpn_service.application.admin_dashboard import AdminDashboardService
from vpn_service.config import Settings
from vpn_service.domain.enums import AuthTokenStatus, NodeStatus
from vpn_service.http.client_ip import client_ip
from vpn_service.persistence.database import Database
from vpn_service.persistence.models import Canary, CanaryAuthToken, Node, User
from vpn_service.security.admin_password import verify_admin_password
from vpn_service.security.tokens import TokenHasher
from vpn_service.worker.node_snapshot_watchdog import NodeSnapshotWatchdog

router = APIRouter(prefix="/admin", tags=["admin"])
logger = logging.getLogger(__name__)
_AUTH_CACHE_KEY = secrets.token_bytes(32)
_AUTH_CACHE: dict[bytes, float] = {}
_AUTH_CACHE_TTL_SECONDS = 300


class AdminRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AdminNodeCreate(AdminRequest):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)] = 443
    country_code: Annotated[str, Field(pattern=r"^[A-Z]{2}$")]
    provider: Annotated[str, Field(min_length=1, max_length=100)]
    capacity_users: Annotated[int, Field(gt=0, le=1_000_000)]


class AdminNodeAction(AdminRequest):
    action: Literal[
        "issue_current_token",
        "issue_next_token",
        "promote_token",
        "revoke_token",
        "activate",
        "block",
        "recover",
        "drain_prepare",
        "drain_finalize",
        "set_capacity",
    ]
    capacity_users: Annotated[int, Field(gt=0, le=1_000_000)] | None = None
    token_id: uuid.UUID | None = None


class AdminCanaryCreate(AdminRequest):
    name: Annotated[str, Field(min_length=1, max_length=100)]


@router.get("")
async def admin_index(request: Request):
    _require_admin(request)
    return _asset_response("index.html", "text/html; charset=utf-8")


@router.get("/assets/{asset_name}")
async def admin_asset(request: Request, asset_name: str):
    _require_admin(request)
    content_types = {
        "admin.css": "text/css; charset=utf-8",
        "admin.js": "text/javascript; charset=utf-8",
    }
    content_type = content_types.get(asset_name)
    if content_type is None:
        raise HTTPException(status_code=404)
    return _asset_response(asset_name, content_type)


@router.get("/api/overview")
async def admin_overview(request: Request):
    _require_admin(request)
    return await _dashboard(request).overview()


@router.get("/api/users")
async def admin_users(request: Request, limit: int = 200):
    _require_admin(request)
    return await _dashboard(request).users(limit=max(1, min(limit, 500)))


@router.get("/api/nodes")
async def admin_nodes(request: Request):
    _require_admin(request)
    return await _dashboard(request).nodes()


@router.get("/api/events")
async def admin_events(request: Request, limit: int = 100):
    _require_admin(request)
    return await _dashboard(request).recent_events(limit=max(1, min(limit, 500)))


@router.post("/api/nodes")
async def admin_node_add(request: Request, payload: AdminNodeCreate):
    _require_admin(request)
    _require_admin_action(request)
    database = _database(request)
    result = await _add_node(
        database,
        argparse.Namespace(
            name=payload.name,
            host=payload.host,
            port=payload.port,
            country_code=payload.country_code,
            provider=payload.provider,
            capacity_users=payload.capacity_users,
        ),
    )
    _audit(request, "node_add", str(result["node_id"]))
    return result


@router.post("/api/nodes/{node_id}/actions")
async def admin_node_action(
    request: Request,
    node_id: uuid.UUID,
    payload: AdminNodeAction,
):
    _require_admin(request)
    _require_admin_action(request)
    database = _database(request)
    settings: Settings = request.app.state.settings
    args = argparse.Namespace(node_id=str(node_id))
    try:
        if payload.action == "issue_current_token":
            args.status = AuthTokenStatus.CURRENT.value
            result = await _issue_node_token(database, settings, args)
        elif payload.action == "issue_next_token":
            args.status = AuthTokenStatus.NEXT.value
            result = await _issue_node_token(database, settings, args)
        elif payload.action in {"promote_token", "revoke_token"}:
            if payload.token_id is None:
                raise RuntimeError("token_id is required")
            args.token_id = str(payload.token_id)
            if payload.action == "promote_token":
                result = await _promote_node_token(database, args)
            else:
                result = await _revoke_node_token(database, args)
        elif payload.action == "activate":
            result = await _activate_node(database, args)
        elif payload.action == "drain_prepare":
            result = await _prepare_node_drain(database, settings, args)
        elif payload.action == "drain_finalize":
            result = await _finalize_node_drain(database, args)
        elif payload.action == "block":
            result = await _block_node(database, settings, node_id)
        elif payload.action == "recover":
            result = await _recover_node(database, node_id)
        elif payload.action == "set_capacity":
            if payload.capacity_users is None:
                raise RuntimeError("capacity_users is required")
            result = await _set_node_capacity(database, node_id, payload.capacity_users)
        else:
            raise HTTPException(status_code=400)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit(request, f"node_{payload.action}", str(node_id))
    return result


@router.post("/api/canaries")
async def admin_canary_add(request: Request, payload: AdminCanaryCreate):
    _require_admin(request)
    _require_admin_action(request)
    database = _database(request)
    settings: Settings = request.app.state.settings
    canary_id = uuid.uuid4()
    issued = TokenHasher(settings).issue("canary")
    async with database.sessions.begin() as session:
        session.add(Canary(id=canary_id, name=payload.name, status="active"))
        session.add(
            CanaryAuthToken(
                id=uuid.uuid4(),
                canary_id=canary_id,
                key_id=issued.key_id,
                token_hash=issued.digest,
                status=AuthTokenStatus.CURRENT.value,
            )
        )
    result = {
        "canary_id": str(canary_id),
        "name": payload.name,
        "canary_token": issued.raw,
        "warning": "Сохраните токен сейчас: повторно получить его нельзя.",
    }
    _audit(request, "canary_add", str(canary_id))
    return result


async def _block_node(
    database: Database,
    settings: Settings,
    node_id: uuid.UUID,
) -> dict[str, object]:
    async with database.sessions.begin() as session:
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None:
            raise RuntimeError("node not found")
        if node.status == NodeStatus.DEAD.value:
            raise RuntimeError("dead node cannot be blocked")
        now = await session.scalar(select(func.now()))
        assert now is not None
        node.status = NodeStatus.BLOCKED.value
        node.recovery_ready = False
        await enqueue_admin_alert(
            session,
            event_name="node_blocked",
            idempotency_key=f"admin-alert:node-blocked:manual:{node.id}:{now.isoformat()}",
            aggregate_id=node.id,
            data={"node_id": str(node.id), "node_name": node.name, "reason": "manual"},
            now=now,
        )
    watchdog = NodeSnapshotWatchdog(database.sessions, settings)
    reassigned, without_capacity = await watchdog.reassign_blocked_users()
    return {
        "node_id": str(node_id),
        "status": NodeStatus.BLOCKED.value,
        "reassigned_users": reassigned,
        "users_without_capacity": without_capacity,
    }


async def _recover_node(database: Database, node_id: uuid.UUID) -> dict[str, object]:
    async with database.sessions.begin() as session:
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None:
            raise RuntimeError("node not found")
        if node.status != NodeStatus.BLOCKED.value or not node.recovery_ready:
            raise RuntimeError("blocked node requires successful canary recovery checks")
        node.status = NodeStatus.WARMING.value
        node.failed_checks = 0
        node.successful_checks = 0
        node.recovery_ready = False
    return {"node_id": str(node_id), "status": NodeStatus.WARMING.value}


async def _set_node_capacity(
    database: Database,
    node_id: uuid.UUID,
    capacity_users: int,
) -> dict[str, object]:
    async with database.sessions.begin() as session:
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None:
            raise RuntimeError("node not found")
        assigned = int(
            await session.scalar(
                select(func.count(User.id)).where(User.assigned_node_id == node_id)
            )
            or 0
        )
        if capacity_users < assigned:
            raise RuntimeError("capacity cannot be lower than currently assigned users")
        node.capacity_users = capacity_users
    return {"node_id": str(node_id), "capacity_users": capacity_users}


def _require_admin(request: Request) -> None:
    settings: Settings = request.app.state.settings
    encoded_hash = settings.admin_panel_password_hash
    if not settings.admin_panel_enabled or encoded_hash is None:
        raise HTTPException(status_code=404)
    authorization = request.headers.get("authorization", "")
    encoded_hash_value = encoded_hash.get_secret_value()
    cache_key = hmac.digest(
        _AUTH_CACHE_KEY,
        (encoded_hash_value + "\0" + authorization).encode(),
        "sha256",
    )
    now = time.monotonic()
    if _AUTH_CACHE.get(cache_key, 0) > now:
        return
    username = ""
    password = ""
    if authorization.startswith("Basic "):
        try:
            decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (binascii.Error, UnicodeError, ValueError):
            pass
    username_valid = hmac.compare_digest(username, settings.admin_panel_username)
    password_valid = verify_admin_password(
        password,
        encoded_hash_value,
    )
    if not username_valid or not password_valid:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="Virgo Admin", charset="UTF-8"'},
        )
    if len(_AUTH_CACHE) >= 256:
        _AUTH_CACHE.clear()
    _AUTH_CACHE[cache_key] = now + _AUTH_CACHE_TTL_SECONDS


def _require_admin_action(request: Request) -> None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json" or request.headers.get("x-admin-action") != "1":
        raise HTTPException(status_code=403, detail="Admin action confirmation is required")


def _dashboard(request: Request) -> AdminDashboardService:
    service: AdminDashboardService | None = request.app.state.admin_dashboard_service
    if service is None:
        raise HTTPException(status_code=503)
    return service


def _database(request: Request) -> Database:
    database: Database | None = request.app.state.database
    if database is None:
        raise HTTPException(status_code=503)
    return database


def _asset_response(name: str, content_type: str):
    from starlette.responses import Response

    body = files("vpn_service").joinpath("assets/admin", name).read_bytes()
    return Response(
        body,
        media_type=content_type,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'"
            ),
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


def _audit(request: Request, action: str, target_id: str) -> None:
    logger.info(
        "admin_action",
        extra={
            "event_data": {
                "event": "admin_action",
                "actor": request.app.state.settings.admin_panel_username,
                "action": action,
                "target_id": target_id,
                "source_ip": client_ip(request, request.app.state.settings.trusted_proxy_cidrs),
            }
        },
    )
