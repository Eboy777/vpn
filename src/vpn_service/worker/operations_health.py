from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.admin_alerts import enqueue_admin_alert
from vpn_service.config import Settings
from vpn_service.domain.enums import NodeStatus
from vpn_service.persistence.models import Node, NodeRuntimeMetric


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
            bucket = int(now.timestamp()) // self._settings.operations_alert_cooldown_seconds
            alert_count = 0
            for node in nodes:
                for problem, value in self._problems(now, runtimes.get(node.id)):
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
        thresholds = (
            ("cpu_high", metric.cpu_percent, self._settings.operations_cpu_warning_percent),
            (
                "memory_high",
                metric.memory_percent,
                self._settings.operations_memory_warning_percent,
            ),
            ("disk_high", metric.disk_percent, self._settings.operations_disk_warning_percent),
        )
        for name, value, threshold in thresholds:
            if value >= threshold:
                problems.append((name, f"{value:.1f}%"))
        if metric.tls_expires_at is not None:
            remaining = metric.tls_expires_at.astimezone(UTC) - now
            if remaining <= timedelta(days=self._settings.operations_tls_warning_days):
                problems.append(("tls_expiring", f"{max(0, remaining.days)}d"))
        return problems


async def _transaction_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)
