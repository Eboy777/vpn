from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.persistence.models import (
    Device,
    ExtensionInstallation,
    Node,
    NodeAuthToken,
    NodeCheckEvent,
    NodeRuntimeMetric,
    NodeUserTraffic,
    Payment,
    User,
    UserActivityEvent,
    VpnSession,
)


class AdminDashboardService:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def overview(self) -> dict[str, Any]:
        async with self._sessions() as session:
            now = await _database_now(session)
            since = now - timedelta(hours=24)
            values = {
                "extension_installations": await session.scalar(
                    select(func.count(ExtensionInstallation.installation_id))
                ),
                "extension_launches": await session.scalar(
                    select(func.coalesce(func.sum(ExtensionInstallation.launch_count), 0))
                ),
                "registrations": await session.scalar(select(func.count(User.id))),
                "free_active": await session.scalar(
                    select(func.count(User.id)).where(
                        User.status == "active",
                        User.trial_expires_at > now,
                        or_(
                            User.subscription_expires_at.is_(None),
                            User.subscription_expires_at <= now,
                        ),
                    )
                ),
                "paid_active": await session.scalar(
                    select(func.count(User.id)).where(
                        User.status == "active", User.subscription_expires_at > now
                    )
                ),
                "payment_links_created": await session.scalar(select(func.count(Payment.id))),
                "active_vpn_sessions": await session.scalar(
                    select(func.count(VpnSession.id)).where(
                        VpnSession.status == "active",
                        VpnSession.last_seen_at > now - timedelta(minutes=3),
                    )
                ),
                "connection_errors_24h": await session.scalar(
                    select(func.count(UserActivityEvent.event_id)).where(
                        UserActivityEvent.event_type == "connection_error",
                        UserActivityEvent.received_at >= since,
                    )
                ),
                "active_nodes": await session.scalar(
                    select(func.count(Node.id)).where(Node.status == "active")
                ),
                "blocked_nodes": await session.scalar(
                    select(func.count(Node.id)).where(Node.status == "blocked")
                ),
                "traffic_input_bytes": await session.scalar(
                    select(func.coalesce(func.sum(NodeUserTraffic.input_bytes), 0))
                ),
                "traffic_output_bytes": await session.scalar(
                    select(func.coalesce(func.sum(NodeUserTraffic.output_bytes), 0))
                ),
            }
            return {
                **{key: int(value or 0) for key, value in values.items()},
                "generated_at": _format(now),
                "download_count_note": (
                    "Первый запуск расширения; фактические скачивания доступны только "
                    "в кабинете магазина расширений."
                ),
            }

    async def users(self, *, limit: int = 200) -> dict[str, Any]:
        async with self._sessions() as session:
            now = await _database_now(session)
            users = list(
                (
                    await session.scalars(
                        select(User).order_by(User.created_at.desc()).limit(limit)
                    )
                ).all()
            )
            user_ids = [user.id for user in users]
            devices = (
                list(
                    (
                        await session.scalars(
                            select(Device)
                            .where(Device.user_id.in_(user_ids))
                            .order_by(Device.last_seen_at.desc().nullslast())
                        )
                    ).all()
                )
                if user_ids
                else []
            )
            traffic_rows = (
                (
                    await session.execute(
                        select(
                            NodeUserTraffic.user_id,
                            func.sum(NodeUserTraffic.input_bytes),
                            func.sum(NodeUserTraffic.output_bytes),
                            func.sum(NodeUserTraffic.total_connections),
                            func.sum(NodeUserTraffic.current_connections),
                            func.sum(NodeUserTraffic.total_errors),
                            func.sum(NodeUserTraffic.connection_seconds),
                        )
                        .where(NodeUserTraffic.user_id.in_(user_ids))
                        .group_by(NodeUserTraffic.user_id)
                    )
                ).all()
                if user_ids
                else []
            )
            session_rows = (
                (
                    await session.execute(
                        select(
                            VpnSession.user_id,
                            func.count(VpnSession.id),
                            func.sum(
                                func.extract(
                                    "epoch",
                                    func.coalesce(VpnSession.ended_at, VpnSession.last_seen_at)
                                    - VpnSession.started_at,
                                )
                            ),
                        )
                        .where(VpnSession.user_id.in_(user_ids))
                        .group_by(VpnSession.user_id)
                    )
                ).all()
                if user_ids
                else []
            )

            devices_by_user: dict[uuid.UUID, list[Device]] = {}
            for device in devices:
                if device.user_id is not None:
                    devices_by_user.setdefault(device.user_id, []).append(device)
            traffic = {row[0]: row[1:] for row in traffic_rows}
            sessions = {row[0]: row[1:] for row in session_rows}
            result = []
            for user in users:
                user_devices = devices_by_user.get(user.id, [])
                latest_device = user_devices[0] if user_devices else None
                traffic_values = traffic.get(user.id, (0, 0, 0, 0, 0, 0))
                session_values = sessions.get(user.id, (0, 0))
                if user.status == "blocked":
                    access = "blocked"
                elif (
                    user.subscription_expires_at is not None and user.subscription_expires_at > now
                ):
                    access = "paid"
                elif user.trial_expires_at is not None and user.trial_expires_at > now:
                    access = "free"
                else:
                    access = "expired"
                result.append(
                    {
                        "id": str(user.id),
                        "telegram_id": user.telegram_id,
                        "status": user.status,
                        "access": access,
                        "assigned_node_id": (
                            str(user.assigned_node_id) if user.assigned_node_id else None
                        ),
                        "node_selection_mode": user.node_selection_mode,
                        "devices": len(user_devices),
                        "last_seen_at": _optional_time(
                            latest_device.last_seen_at if latest_device else None
                        ),
                        "last_ip": latest_device.last_ip if latest_device else None,
                        "input_bytes": int(traffic_values[0] or 0),
                        "output_bytes": int(traffic_values[1] or 0),
                        "total_connections": int(traffic_values[2] or 0),
                        "current_connections": int(traffic_values[3] or 0),
                        "traffic_errors": int(traffic_values[4] or 0),
                        "connection_seconds": int(traffic_values[5] or 0),
                        "vpn_sessions": int(session_values[0] or 0),
                        "vpn_duration_seconds": int(session_values[1] or 0),
                        "created_at": _format(user.created_at),
                    }
                )
            return {"users": result, "generated_at": _format(now)}

    async def nodes(self) -> dict[str, Any]:
        async with self._sessions() as session:
            now = await _database_now(session)
            nodes = list((await session.scalars(select(Node).order_by(Node.name))).all())
            runtime = {
                item.node_id: item
                for item in (await session.scalars(select(NodeRuntimeMetric))).all()
            }
            tokens_by_node: dict[uuid.UUID, list[NodeAuthToken]] = {}
            for token in (
                await session.scalars(
                    select(NodeAuthToken).order_by(NodeAuthToken.created_at.desc())
                )
            ).all():
                tokens_by_node.setdefault(token.node_id, []).append(token)
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
                            func.sum(NodeUserTraffic.total_connections),
                            func.sum(NodeUserTraffic.total_errors),
                        ).group_by(NodeUserTraffic.node_id)
                    )
                ).all()
            }
            latest_checks: dict[uuid.UUID, NodeCheckEvent] = {}
            checks = list(
                (
                    await session.scalars(
                        select(NodeCheckEvent).order_by(NodeCheckEvent.checked_at.desc())
                    )
                ).all()
            )
            for check in checks:
                latest_checks.setdefault(check.node_id, check)
            result = []
            for node in nodes:
                metric = runtime.get(node.id)
                traffic_values = traffic.get(node.id, (0, 0, 0, 0, 0))
                check = latest_checks.get(node.id)
                target_results = check.response_json.get("targets", []) if check else []
                successful_latencies = [
                    float(item["latency_ms"])
                    for item in target_results
                    if item.get("success") and item.get("latency_ms") is not None
                ]
                result.append(
                    {
                        "id": str(node.id),
                        "name": node.name,
                        "host": node.host,
                        "port": node.port,
                        "country_code": node.country_code,
                        "provider": node.provider,
                        "status": node.status,
                        "capacity_users": node.capacity_users,
                        "assigned_users": int(assigned.get(node.id, 0)),
                        "free_capacity": max(
                            0, node.capacity_users - int(assigned.get(node.id, 0))
                        ),
                        "last_sync_at": _optional_time(node.last_sync_at),
                        "snapshot_valid_until": _optional_time(node.applied_snapshot_valid_until),
                        "snapshot_ack_failures": node.snapshot_ack_failures,
                        "last_check_at": _optional_time(node.last_check_at),
                        "failed_checks": node.failed_checks,
                        "successful_checks": node.successful_checks,
                        "recovery_ready": node.recovery_ready,
                        "quality_latency_ms": (
                            round(sum(successful_latencies) / len(successful_latencies), 3)
                            if successful_latencies
                            else None
                        ),
                        "quality_outcome": (check.response_json.get("outcome") if check else None),
                        "input_bytes": int(traffic_values[0] or 0),
                        "output_bytes": int(traffic_values[1] or 0),
                        "current_connections": int(traffic_values[2] or 0),
                        "total_connections": int(traffic_values[3] or 0),
                        "traffic_errors": int(traffic_values[4] or 0),
                        "runtime": (
                            {
                                "cpu_percent": metric.cpu_percent,
                                "memory_percent": metric.memory_percent,
                                "disk_percent": metric.disk_percent,
                                "network_rx_bytes": metric.network_rx_bytes,
                                "network_tx_bytes": metric.network_tx_bytes,
                                "gost_up": metric.gost_up,
                                "sync_agent_up": metric.sync_agent_up,
                                "tls_expires_at": _optional_time(metric.tls_expires_at),
                                "observed_at": _format(metric.observed_at),
                                "stale": metric.observed_at < now - timedelta(minutes=2),
                            }
                            if metric
                            else None
                        ),
                        "tokens": [
                            {
                                "id": str(token.id),
                                "status": token.status,
                                "expires_at": _optional_time(token.expires_at),
                                "created_at": _format(token.created_at),
                            }
                            for token in tokens_by_node.get(node.id, [])[:10]
                        ],
                    }
                )
            return {"nodes": result, "generated_at": _format(now)}

    async def recent_events(self, *, limit: int = 100) -> dict[str, Any]:
        async with self._sessions() as session:
            events = list(
                (
                    await session.scalars(
                        select(UserActivityEvent)
                        .order_by(UserActivityEvent.received_at.desc())
                        .limit(limit)
                    )
                ).all()
            )
            return {
                "events": [
                    {
                        "event_id": str(event.event_id),
                        "user_id": str(event.user_id),
                        "device_id": str(event.device_id),
                        "node_id": str(event.node_id) if event.node_id else None,
                        "event_type": event.event_type,
                        "error_code": event.error_code,
                        "source_ip": event.source_ip,
                        "received_at": _format(event.received_at),
                    }
                    for event in events
                ]
            }


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)


def _format(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _optional_time(value: datetime | None) -> str | None:
    return _format(value) if value is not None else None
