from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.admin_alerts import enqueue_admin_alert
from vpn_service.config import Settings
from vpn_service.domain.enums import NodeStatus
from vpn_service.persistence.models import Node, NodeRuntimeMetric, NodeUserTraffic, User

_WARNING_RATIO = 0.70
_CRITICAL_RATIO = 0.80
_NODE_CONNECTION_LIMIT = 5_000


class OperationsHealthWorker:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.check_once()
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._settings.operations_health_poll_seconds,
                )
            except TimeoutError:
                pass

    async def check_once(self) -> int:
        if not self._settings.admin_telegram_chat_ids_json:
            return 0
        async with self._sessions.begin() as session:
            now = await _transaction_now(session)
            nodes = list(
                (
                    await session.scalars(
                        select(Node).where(
                            Node.status.in_(
                                [
                                    NodeStatus.ACTIVE.value,
                                    NodeStatus.QUIESCING.value,
                                    NodeStatus.DRAINING.value,
                                ]
                            )
                        )
                    )
                ).all()
            )
            runtimes = {
                metric.node_id: metric
                for metric in (
                    await session.scalars(
                        select(NodeRuntimeMetric).where(
                            NodeRuntimeMetric.node_id.in_([node.id for node in nodes])
                        )
                    )
                ).all()
            }
            assigned = dict(
                (
                    await session.execute(
                        select(User.assigned_node_id, func.count(User.id))
                        .where(User.assigned_node_id.in_([node.id for node in nodes]))
                        .group_by(User.assigned_node_id)
                    )
                ).all()
            )
            connections = dict(
                (
                    await session.execute(
                        select(
                            NodeUserTraffic.node_id,
                            func.sum(NodeUserTraffic.current_connections),
                        )
                        .where(NodeUserTraffic.node_id.in_([node.id for node in nodes]))
                        .group_by(NodeUserTraffic.node_id)
                    )
                ).all()
            )
            bucket = int(now.timestamp()) // self._settings.operations_alert_cooldown_seconds
            alert_count = 0
            for node in nodes:
                for problem, value in self._problems(
                    now,
                    runtimes.get(node.id),
                    assigned_users=int(assigned.get(node.id, 0)),
                    capacity_users=node.capacity_users,
                    current_connections=int(connections.get(node.id, 0) or 0),
                ):
                    await enqueue_admin_alert(
                        session,
                        event_name="node_health_warning",
                        idempotency_key=(f"admin-alert:node-health:{node.id}:{problem}:{bucket}"),
                        aggregate_id=node.id,
                        data={
                            "node_id": str(node.id),
                            "node_name": node.name,
                            "problem": problem,
                            "value": value,
                        },
                        now=now,
                    )
                    alert_count += 1
            return alert_count

    def _problems(
        self,
        now: datetime,
        metric: NodeRuntimeMetric | None,
        *,
        assigned_users: int = 0,
        capacity_users: int = 1,
        current_connections: int = 0,
    ) -> list[tuple[str, str]]:
        if metric is None:
            return [("telemetry_missing", "no runtime report")]
        age = max(0, int((now - metric.observed_at.astimezone(UTC)).total_seconds()))
        if age > self._settings.operations_node_telemetry_stale_seconds:
            return [("telemetry_stale", f"{age}s")]
        problems: list[tuple[str, str]] = []
        if not metric.gost_up:
            problems.append(("gost_down", "down"))
        if not metric.sync_agent_up:
            problems.append(("sync_agent_down", "down"))
        resources = (
            ("cpu", metric.cpu_percent),
            ("memory", metric.memory_percent),
            ("disk", metric.disk_percent),
        )
        for name, value in resources:
            severity = _severity(value / 100)
            if severity is not None:
                problems.append((f"{name}_{severity}", f"{value:.1f}%"))
        capacity_ratio = assigned_users / max(1, capacity_users)
        capacity_severity = _severity(capacity_ratio)
        if capacity_severity is not None:
            problems.append(
                (
                    f"capacity_{capacity_severity}",
                    f"{assigned_users}/{capacity_users} ({capacity_ratio * 100:.1f}%)",
                )
            )
        connection_ratio = current_connections / _NODE_CONNECTION_LIMIT
        connection_severity = _severity(connection_ratio)
        if connection_severity is not None:
            problems.append(
                (
                    f"connections_{connection_severity}",
                    f"{current_connections}/{_NODE_CONNECTION_LIMIT} "
                    f"({connection_ratio * 100:.1f}%)",
                )
            )
        if metric.tls_expires_at is not None:
            remaining = metric.tls_expires_at.astimezone(UTC) - now
            if remaining <= timedelta(days=self._settings.operations_tls_warning_days):
                problems.append(("tls_expiring", f"{max(0, remaining.days)}d"))
        return problems


def _severity(ratio: float) -> str | None:
    if ratio >= _CRITICAL_RATIO:
        return "critical"
    if ratio >= _WARNING_RATIO:
        return "warning"
    return None


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
