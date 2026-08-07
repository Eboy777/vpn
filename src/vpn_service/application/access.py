from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.device_auth import AuthenticatedDevice
from vpn_service.application.node_assignment import (
    active_node_loads,
    choose_node,
    lock_active_nodes,
)
from vpn_service.config import Settings
from vpn_service.domain.enums import NodeSelectionMode, NodeStatus, UserStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.persistence.models import Node, User
from vpn_service.persistence.rate_limits import consume_rate_limit
from vpn_service.security.credentials import ProxyCredentialsCipher
from vpn_service.security.tokens import TokenHasher


class AccessState(StrEnum):
    TRIAL = "trial"
    PAID = "paid"
    EXPIRED = "expired"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class PublicNode:
    id: uuid.UUID
    name: str
    host: str
    port: int
    country_code: str


@dataclass(frozen=True, slots=True)
class AccessResult:
    device_id: uuid.UUID
    state: AccessState
    trial_expires_at: datetime | None
    subscription_expires_at: datetime | None
    access_expires_at: datetime | None
    node_selection_mode: str
    node: PublicNode | None
    proxy_username: str | None
    proxy_password: str | None
    server_time: datetime


@dataclass(frozen=True, slots=True)
class SelectableNode:
    id: uuid.UUID
    name: str
    country_code: str
    selected: bool


@dataclass(frozen=True, slots=True)
class NodeListResult:
    nodes: tuple[SelectableNode, ...]
    node_selection_mode: str
    generated_at: datetime


@dataclass(frozen=True, slots=True)
class NodeSelectionResult:
    assigned_node: PublicNode
    node_selection_mode: str
    changed: bool


class AccessService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._credentials = ProxyCredentialsCipher(settings)
        self._tokens = TokenHasher(settings)

    async def status(self, device: AuthenticatedDevice) -> AccessResult:
        await self._enforce_rate_limit(
            scope="status-minute",
            subject_value=str(device.device_id),
            limit=self._settings.status_rate_per_minute,
        )
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            user = await _locked_user(session, device.user_id)
            state = _access_state(user, now)
            node: Node | None = None
            if state in (AccessState.TRIAL, AccessState.PAID):
                if user.assigned_node_id is not None:
                    candidate = await session.get(Node, user.assigned_node_id)
                    if candidate is not None and candidate.status == NodeStatus.ACTIVE.value:
                        node = candidate
                if node is None:
                    node = await choose_node(
                        session,
                        now=now,
                        hard_capacity=self._settings.node_assignment_hard_capacity,
                    )
                    user.assigned_node_id = node.id if node is not None else None
                    user.node_selection_mode = NodeSelectionMode.AUTO.value

            password = None
            if node is not None:
                password = self._credentials.decrypt(user.id, user.proxy_password_ciphertext)
            return AccessResult(
                device_id=device.device_id,
                state=state,
                trial_expires_at=user.trial_expires_at,
                subscription_expires_at=user.subscription_expires_at,
                access_expires_at=_access_expires_at(user),
                node_selection_mode=user.node_selection_mode,
                node=_public_node(node) if node is not None else None,
                proxy_username=user.proxy_username if node is not None else None,
                proxy_password=password,
                server_time=now,
            )

    async def nodes(self, device: AuthenticatedDevice) -> NodeListResult:
        await self._enforce_rate_limit(
            scope="nodes-minute",
            subject_value=str(device.device_id),
            limit=self._settings.nodes_rate_per_minute,
        )
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            user = await _locked_user(session, device.user_id)
            _require_paid(user, now)
            nodes = list(
                (
                    await session.scalars(
                        select(Node)
                        .where(Node.status == NodeStatus.ACTIVE.value)
                        .order_by(Node.country_code, Node.name, Node.id)
                    )
                ).all()
            )
            loads = await active_node_loads(session, now=now)
            available = [
                node
                for node in nodes
                if node.id == user.assigned_node_id
                or not self._settings.node_assignment_hard_capacity
                or loads.get(node.id, 0) < node.capacity_users
            ]
            return NodeListResult(
                nodes=tuple(
                    SelectableNode(
                        id=node.id,
                        name=node.name,
                        country_code=node.country_code,
                        selected=node.id == user.assigned_node_id,
                    )
                    for node in available
                ),
                node_selection_mode=user.node_selection_mode,
                generated_at=now,
            )

    async def select_node(
        self,
        device: AuthenticatedDevice,
        requested_node_id: uuid.UUID | None,
    ) -> NodeSelectionResult:
        await self._enforce_rate_limit(
            scope="node-select-minute",
            subject_value=str(device.user_id),
            limit=self._settings.node_select_rate_per_minute,
        )
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            user = await _locked_user(session, device.user_id)
            _require_paid(user, now)
            previous = (user.assigned_node_id, user.node_selection_mode)
            active_nodes = await lock_active_nodes(session)
            active_by_id = {node.id: node for node in active_nodes}

            if requested_node_id is not None:
                node = active_by_id.get(requested_node_id)
                if node is None:
                    exists = await session.get(Node, requested_node_id)
                    if exists is None:
                        raise ApplicationError(404, "NODE_NOT_FOUND", "Node was not found")
                    raise ApplicationError(409, "NODE_UNAVAILABLE", "Node is unavailable")
                if requested_node_id != user.assigned_node_id:
                    loads = await active_node_loads(session, now=now)
                    if (
                        self._settings.node_assignment_hard_capacity
                        and loads.get(node.id, 0) >= node.capacity_users
                    ):
                        raise ApplicationError(409, "NODE_UNAVAILABLE", "Node is unavailable")
                user.assigned_node_id = node.id
                user.node_selection_mode = NodeSelectionMode.MANUAL.value
            else:
                current = active_by_id.get(user.assigned_node_id)
                if user.node_selection_mode == NodeSelectionMode.AUTO.value and current is not None:
                    node = current
                else:
                    loads = await active_node_loads(session, now=now)
                    eligible = (
                        [
                            candidate
                            for candidate in active_nodes
                            if loads.get(candidate.id, 0) < candidate.capacity_users
                            or candidate.id == user.assigned_node_id
                        ]
                        if self._settings.node_assignment_hard_capacity
                        else active_nodes
                    )
                    if not eligible:
                        raise ApplicationError(409, "NO_ACTIVE_NODE", "No active node is available")
                    node = min(
                        eligible,
                        key=lambda candidate: (
                            loads.get(candidate.id, 0) / candidate.capacity_users,
                            candidate.id,
                        ),
                    )
                user.assigned_node_id = node.id
                user.node_selection_mode = NodeSelectionMode.AUTO.value

            changed = previous != (user.assigned_node_id, user.node_selection_mode)
            return NodeSelectionResult(
                assigned_node=_public_node(node),
                node_selection_mode=user.node_selection_mode,
                changed=changed,
            )

    async def _enforce_rate_limit(
        self,
        *,
        scope: str,
        subject_value: str,
        limit: int,
    ) -> None:
        subject = self._tokens.opaque_subject(scope, subject_value)
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            decision = await consume_rate_limit(
                session,
                scope=scope,
                subject_hash=subject,
                limit=limit,
                window_seconds=60,
                now=now,
            )
        if not decision.allowed:
            raise ApplicationError(
                429,
                "RATE_LIMITED",
                "Rate limit exceeded",
                headers={
                    "Retry-After": str(decision.retry_after),
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": str(decision.remaining),
                },
            )


async def _database_now(session: AsyncSession) -> datetime:
    now = await session.scalar(select(func.now()))
    assert now is not None
    return now.astimezone(UTC)


async def _locked_user(session: AsyncSession, user_id: uuid.UUID) -> User:
    user = (
        await session.execute(select(User).where(User.id == user_id).with_for_update())
    ).scalar_one_or_none()
    if user is None:  # A bound device must always refer to an existing user.
        raise ApplicationError(401, "INVALID_DEVICE_TOKEN", "Device token is invalid")
    return user


def _access_state(user: User, now: datetime) -> AccessState:
    if user.status == UserStatus.BLOCKED.value:
        return AccessState.BLOCKED
    if user.subscription_expires_at is not None and user.subscription_expires_at > now:
        return AccessState.PAID
    if user.trial_expires_at is not None and user.trial_expires_at > now:
        return AccessState.TRIAL
    return AccessState.EXPIRED


def _access_expires_at(user: User) -> datetime | None:
    dates = [date for date in (user.trial_expires_at, user.subscription_expires_at) if date]
    return max(dates) if dates else None


def _require_paid(user: User, now: datetime) -> None:
    state = _access_state(user, now)
    if state == AccessState.BLOCKED:
        raise ApplicationError(403, "USER_BLOCKED", "User is blocked")
    if state != AccessState.PAID:
        raise ApplicationError(
            403,
            "PAID_SUBSCRIPTION_REQUIRED",
            "A paid subscription is required",
        )


def _public_node(node: Node) -> PublicNode:
    return PublicNode(
        id=node.id,
        name=node.name,
        host=node.host,
        port=node.port,
        country_code=node.country_code,
    )
