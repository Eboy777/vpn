from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.persistence.models import (
    ExtensionInstallation,
    Node,
    NodeCheckEvent,
    NodeRuntimeMetric,
    NodeUserTraffic,
    Payment,
    User,
    UserActivityEvent,
    VpnSession,
)


class MetricsService:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def render(self) -> str:
        async with self._sessions() as session:
            now = await _database_now(session)
            lines = [
                "# HELP virgo_extension_installations_total Unique first extension launches.",
                "# TYPE virgo_extension_installations_total gauge",
                "virgo_extension_installations_total "
                + str(
                    int(
                        await session.scalar(
                            select(func.count(ExtensionInstallation.installation_id))
                        )
                        or 0
                    )
                ),
                "# HELP virgo_extension_launches_total Extension launch events received.",
                "# TYPE virgo_extension_launches_total gauge",
                "virgo_extension_launches_total "
                + str(
                    int(
                        await session.scalar(
                            select(func.coalesce(func.sum(ExtensionInstallation.launch_count), 0))
                        )
                        or 0
                    )
                ),
                "# HELP virgo_registrations_total Registered Telegram users.",
                "# TYPE virgo_registrations_total gauge",
                "virgo_registrations_total "
                + str(int(await session.scalar(select(func.count(User.id))) or 0)),
                "# HELP virgo_payment_links_created_total Created payment records.",
                "# TYPE virgo_payment_links_created_total gauge",
                "virgo_payment_links_created_total "
                + str(int(await session.scalar(select(func.count(Payment.id))) or 0)),
                "# HELP virgo_vpn_sessions_active Recently active extension VPN sessions.",
                "# TYPE virgo_vpn_sessions_active gauge",
                "virgo_vpn_sessions_active "
                + str(
                    int(
                        await session.scalar(
                            select(func.count(VpnSession.id)).where(
                                VpnSession.status == "active",
                                VpnSession.last_seen_at > now - timedelta(minutes=3),
                            )
                        )
                        or 0
                    )
                ),
                "# HELP virgo_connection_errors_24h Extension connection errors in 24 hours.",
                "# TYPE virgo_connection_errors_24h gauge",
                "virgo_connection_errors_24h "
                + str(
                    int(
                        await session.scalar(
                            select(func.count(UserActivityEvent.event_id)).where(
                                UserActivityEvent.event_type == "connection_error",
                                UserActivityEvent.received_at >= now - timedelta(hours=24),
                            )
                        )
                        or 0
                    )
                ),
            ]
            access_counts = {
                "paid": int(
                    await session.scalar(
                        select(func.count(User.id)).where(
                            User.status == "active", User.subscription_expires_at > now
                        )
                    )
                    or 0
                ),
                "free": int(
                    await session.scalar(
                        select(func.count(User.id)).where(
                            User.status == "active",
                            User.trial_expires_at > now,
                            or_(
                                User.subscription_expires_at.is_(None),
                                User.subscription_expires_at <= now,
                            ),
                        )
                    )
                    or 0
                ),
                "expired_or_blocked": int(
                    await session.scalar(
                        select(func.count(User.id)).where(
                            or_(
                                User.status == "blocked",
                                (
                                    (
                                        User.trial_expires_at.is_(None)
                                        | (User.trial_expires_at <= now)
                                    )
                                    & (
                                        User.subscription_expires_at.is_(None)
                                        | (User.subscription_expires_at <= now)
                                    )
                                ),
                            )
                        )
                    )
                    or 0
                ),
            }
            lines.extend(
                [
                    "# HELP virgo_users User accounts by current access state.",
                    "# TYPE virgo_users gauge",
                    *(
                        f'virgo_users{{access="{label}"}} {value}'
                        for label, value in access_counts.items()
                    ),
                ]
            )
            nodes = list((await session.scalars(select(Node))).all())
            runtimes = {
                metric.node_id: metric
                for metric in (await session.scalars(select(NodeRuntimeMetric))).all()
            }
            assigned = dict(
                (
                    await session.execute(
                        select(User.assigned_node_id, func.count(User.id))
                        .where(User.assigned_node_id.is_not(None))
                        .group_by(User.assigned_node_id)
                    )
                ).all()
            )
            traffic = {
                row[0]: row[1:]
                for row in (
                    await session.execute(
                        select(
                            NodeUserTraffic.node_id,
                            func.sum(NodeUserTraffic.input_bytes),
                            func.sum(NodeUserTraffic.output_bytes),
                            func.sum(NodeUserTraffic.current_connections),
                            func.sum(NodeUserTraffic.total_errors),
                        ).group_by(NodeUserTraffic.node_id)
                    )
                ).all()
            }
            latest_checks: dict[object, NodeCheckEvent] = {}
            for check in (
                await session.scalars(
                    select(NodeCheckEvent).order_by(NodeCheckEvent.checked_at.desc())
                )
            ).all():
                latest_checks.setdefault(check.node_id, check)
            for node in nodes:
                labels = (
                    f'node_id="{node.id}",node="{_label(node.name)}",'
                    f'country="{_label(node.country_code)}",status="{_label(node.status)}"'
                )
                sync_age = (
                    max(0.0, (now - node.last_sync_at).total_seconds())
                    if node.last_sync_at is not None
                    else -1
                )
                values = traffic.get(node.id, (0, 0, 0, 0))
                node_id = str(node.id)
                lines.extend(
                    (
                        f"virgo_node_info{{{labels}}} 1",
                        _metric("virgo_node_assigned_users", node_id, assigned.get(node.id, 0)),
                        _metric("virgo_node_capacity_users", node_id, node.capacity_users),
                        _metric("virgo_node_last_sync_age_seconds", node_id, sync_age),
                        _metric(
                            "virgo_node_snapshot_ack_failures",
                            node_id,
                            node.snapshot_ack_failures,
                        ),
                        _metric("virgo_node_input_bytes_total", node_id, values[0] or 0),
                        _metric("virgo_node_output_bytes_total", node_id, values[1] or 0),
                        _metric("virgo_node_current_connections", node_id, values[2] or 0),
                        _metric("virgo_node_traffic_errors_total", node_id, values[3] or 0),
                    )
                )
                metric = runtimes.get(node.id)
                check = latest_checks.get(node.id)
                if check is not None:
                    targets = check.response_json.get("targets", [])
                    latencies = [
                        float(item["latency_ms"])
                        for item in targets
                        if item.get("success") and item.get("latency_ms") is not None
                    ]
                    lines.extend(
                        (
                            _metric(
                                "virgo_node_canary_up",
                                node_id,
                                int(check.response_json.get("outcome") == "healthy"),
                            ),
                            _metric(
                                "virgo_node_canary_latency_ms",
                                node_id,
                                round(sum(latencies) / len(latencies), 3) if latencies else -1,
                            ),
                        )
                    )
                if metric is not None:
                    runtime_age = max(0.0, (now - metric.observed_at).total_seconds())
                    lines.extend(
                        (
                            _metric("virgo_node_cpu_percent", node_id, metric.cpu_percent),
                            _metric("virgo_node_memory_percent", node_id, metric.memory_percent),
                            _metric("virgo_node_disk_percent", node_id, metric.disk_percent),
                            _metric("virgo_node_gost_up", node_id, int(metric.gost_up)),
                            _metric(
                                "virgo_node_sync_agent_up",
                                node_id,
                                int(metric.sync_agent_up),
                            ),
                            _metric("virgo_node_runtime_age_seconds", node_id, runtime_age),
                            _metric(
                                "virgo_node_tls_expiry_seconds",
                                node_id,
                                max(0.0, (metric.tls_expires_at - now).total_seconds())
                                if metric.tls_expires_at is not None
                                else -1,
                            ),
                        )
                    )
            return "\n".join(lines) + "\n"


def _metric(name: str, node_id: str, value: object) -> str:
    return f'{name}{{node_id="{node_id}"}} {value}'


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
