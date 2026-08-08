from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.node_assignment import choose_node
from vpn_service.config import Settings
from vpn_service.domain.enums import NodeSelectionMode, NodeStatus, UserStatus
from vpn_service.persistence.models import Node, User

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SnapshotWatchdogResult:
    missed_ack_windows: int
    blocked_nodes: int
    reassigned_users: int
    users_without_capacity: int


class NodeSnapshotWatchdog:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            result = await self.inspect_once()
            if result.blocked_nodes:
                logger.error(
                    "node_snapshot_watchdog_blocked",
                    extra={
                        "event_data": {
                            "event": "node_snapshot_watchdog",
                            "blocked_nodes": result.blocked_nodes,
                            "reassigned_users": result.reassigned_users,
                            "users_without_capacity": result.users_without_capacity,
                        }
                    },
                )
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._settings.node_snapshot_watch_interval_seconds,
                )
            except TimeoutError:
                pass

    async def inspect_once(self) -> SnapshotWatchdogResult:
        missed_windows = 0
        blocked_nodes = 0
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            nodes = list(
                (
                    await session.scalars(
                        select(Node)
                        .where(Node.status == NodeStatus.ACTIVE.value)
                        .order_by(Node.id)
                        .with_for_update()
                    )
                ).all()
            )
            for node in nodes:
                missed, should_block = _advance_snapshot_health(
                    node,
                    now=now,
                    settings=self._settings,
                )
                if missed:
                    missed_windows += 1
                if should_block:
                    node.status = NodeStatus.BLOCKED.value
                    node.recovery_ready = False
                    node.snapshot_ack_deadline = None
                    blocked_nodes += 1

        reassigned, without_capacity = await self._reassign_blocked_users()
        return SnapshotWatchdogResult(
            missed_ack_windows=missed_windows,
            blocked_nodes=blocked_nodes,
            reassigned_users=reassigned,
            users_without_capacity=without_capacity,
        )

    async def _reassign_blocked_users(self) -> tuple[int, int]:
        async with self._sessions() as session:
            user_ids = list(
                (
                    await session.scalars(
                        select(User.id)
                        .join(Node, User.assigned_node_id == Node.id)
                        .where(Node.status == NodeStatus.BLOCKED.value)
                        .order_by(User.id)
                    )
                ).all()
            )

        reassigned = 0
        without_capacity = 0
        for user_id in user_ids:
            async with self._sessions.begin() as session:
                user = (
                    await session.execute(select(User).where(User.id == user_id).with_for_update())
                ).scalar_one_or_none()
                if user is None or user.assigned_node_id is None:
                    continue
                source_status = await session.scalar(
                    select(Node.status).where(Node.id == user.assigned_node_id)
                )
                if source_status != NodeStatus.BLOCKED.value:
                    continue
                now = await _database_now(session)
                has_access = user.status == UserStatus.ACTIVE.value and (
                    (user.trial_expires_at is not None and user.trial_expires_at > now)
                    or (
                        user.subscription_expires_at is not None
                        and user.subscription_expires_at > now
                    )
                )
                selected = (
                    await choose_node(
                        session,
                        now=now,
                        hard_capacity=self._settings.node_assignment_hard_capacity,
                    )
                    if has_access
                    else None
                )
                user.assigned_node_id = selected.id if selected is not None else None
                user.node_selection_mode = NodeSelectionMode.AUTO.value
                if selected is None:
                    if has_access:
                        without_capacity += 1
                else:
                    reassigned += 1
        return reassigned, without_capacity


async def _database_now(session: AsyncSession) -> datetime:
    now = await session.scalar(select(func.now()))
    assert now is not None
    return now.astimezone(UTC)


def _advance_snapshot_health(
    node: Node,
    *,
    now: datetime,
    settings: Settings,
) -> tuple[bool, bool]:
    heartbeat_stale = node.last_sync_at is None or node.last_sync_at <= now - timedelta(
        seconds=settings.node_snapshot_heartbeat_timeout_seconds
    )
    applied_lease_expired = (
        node.applied_snapshot_valid_until is None or node.applied_snapshot_valid_until <= now
    )
    pending_ack_due = (
        node.credentials_revision is not None
        and node.applied_credentials_revision != node.credentials_revision
        and node.snapshot_ack_deadline is not None
        and node.snapshot_ack_deadline <= now
    )
    should_block = heartbeat_stale or applied_lease_expired
    if not pending_ack_due:
        return False, should_block

    node.snapshot_ack_failures += 1
    should_block = (
        should_block or node.snapshot_ack_failures >= settings.node_snapshot_max_missed_acks
    )
    if not should_block:
        node.snapshot_ack_deadline = now + timedelta(
            seconds=settings.node_snapshot_ack_timeout_seconds
        )
    return True, should_block
