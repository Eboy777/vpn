from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.node_credentials import AuthenticatedNode
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.schemas import NodeTelemetryRequest
from vpn_service.persistence.models import (
    Node,
    NodeRuntimeMetric,
    NodeTelemetryReport,
    NodeUserTraffic,
    User,
)

_MAX_I64 = 2**63 - 1


class NodeTelemetryService:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def record(
        self,
        identity: AuthenticatedNode,
        *,
        requested_node_id: uuid.UUID,
        payload: NodeTelemetryRequest,
    ) -> dict[str, object]:
        if identity.node_id != requested_node_id:
            raise ApplicationError(
                403,
                "NODE_TOKEN_MISMATCH",
                "Node token does not match the requested node",
            )
        request_hash = _request_hash(payload)
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            observed_at = payload.observed_at.astimezone(UTC)
            if observed_at < now - timedelta(days=1) or observed_at > now + timedelta(minutes=5):
                raise ApplicationError(
                    400,
                    "INVALID_TELEMETRY_TIME",
                    "Telemetry timestamp is outside the accepted window",
                )
            existing = await session.get(NodeTelemetryReport, payload.report_id)
            if existing is not None:
                if existing.node_id != requested_node_id or existing.request_hash != request_hash:
                    raise ApplicationError(409, "REPORT_ID_CONFLICT", "Report ID is already used")
                return {**existing.response_json, "processed": False}
            node = await session.get(Node, requested_node_id)
            if node is None:
                raise ApplicationError(404, "NODE_NOT_FOUND", "Node does not exist")

            usernames = {item.proxy_username for item in payload.clients}
            users = {
                user.proxy_username: user
                for user in (
                    await session.scalars(select(User).where(User.proxy_username.in_(usernames)))
                ).all()
            }
            accepted = 0
            for item in payload.clients:
                user = users.get(item.proxy_username)
                if user is None:
                    continue
                accepted += 1
                statement = insert(NodeUserTraffic).values(
                    id=uuid.uuid4(),
                    node_id=requested_node_id,
                    user_id=user.id,
                    total_connections=item.total_connections,
                    current_connections=item.current_connections,
                    input_bytes=item.input_bytes,
                    output_bytes=item.output_bytes,
                    total_errors=item.total_errors,
                    connection_seconds=item.connection_seconds,
                    last_reported_at=observed_at,
                )
                await session.execute(
                    statement.on_conflict_do_update(
                        constraint="uq_node_user_traffic_node_user",
                        set_={
                            "total_connections": (
                                _saturated_increment(
                                    NodeUserTraffic.total_connections,
                                    statement.excluded.total_connections,
                                )
                            ),
                            "current_connections": statement.excluded.current_connections,
                            "input_bytes": (
                                _saturated_increment(
                                    NodeUserTraffic.input_bytes,
                                    statement.excluded.input_bytes,
                                )
                            ),
                            "output_bytes": (
                                _saturated_increment(
                                    NodeUserTraffic.output_bytes,
                                    statement.excluded.output_bytes,
                                )
                            ),
                            "total_errors": (
                                _saturated_increment(
                                    NodeUserTraffic.total_errors,
                                    statement.excluded.total_errors,
                                )
                            ),
                            "connection_seconds": (
                                _saturated_increment(
                                    NodeUserTraffic.connection_seconds,
                                    statement.excluded.connection_seconds,
                                )
                            ),
                            "last_reported_at": statement.excluded.last_reported_at,
                        },
                    )
                )

            runtime = payload.runtime
            runtime_insert = insert(NodeRuntimeMetric).values(
                node_id=requested_node_id,
                cpu_percent=runtime.cpu_percent,
                memory_percent=runtime.memory_percent,
                disk_percent=runtime.disk_percent,
                network_rx_bytes=runtime.network_rx_bytes,
                network_tx_bytes=runtime.network_tx_bytes,
                gost_up=runtime.gost_up,
                sync_agent_up=runtime.sync_agent_up,
                tls_expires_at=runtime.tls_expires_at,
                observed_at=observed_at,
            )
            await session.execute(
                runtime_insert.on_conflict_do_update(
                    index_elements=[NodeRuntimeMetric.node_id],
                    set_={
                        column: getattr(runtime_insert.excluded, column)
                        for column in (
                            "cpu_percent",
                            "memory_percent",
                            "disk_percent",
                            "network_rx_bytes",
                            "network_tx_bytes",
                            "gost_up",
                            "sync_agent_up",
                            "tls_expires_at",
                            "observed_at",
                        )
                    },
                )
            )
            response: dict[str, object] = {
                "processed": True,
                "node_id": str(requested_node_id),
                "report_id": str(payload.report_id),
                "accepted_clients": accepted,
            }
            session.add(
                NodeTelemetryReport(
                    report_id=payload.report_id,
                    node_id=requested_node_id,
                    observed_at=observed_at,
                    request_hash=request_hash,
                    response_json=response,
                    received_at=now,
                )
            )
            return response


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)


def _saturated_increment(current, increment):
    return current + func.least(increment, _MAX_I64 - current)


def _request_hash(payload: NodeTelemetryRequest) -> str:
    canonical = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()
