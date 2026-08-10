from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.application.admin_alerts import enqueue_admin_alert
from vpn_service.application.discovery import DiscoveryService
from vpn_service.config import Settings
from vpn_service.domain.enums import AuthTokenStatus, NodeStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.http.schemas import CanaryNodeResult, CanaryRunRequest
from vpn_service.persistence.models import (
    Canary,
    CanaryAuthToken,
    CanaryRun,
    Node,
    NodeCheckEvent,
)
from vpn_service.security.tokens import TokenHasher
from vpn_service.worker.node_snapshot_watchdog import NodeSnapshotWatchdog


@dataclass(frozen=True, slots=True)
class AuthenticatedCanary:
    canary_id: uuid.UUID
    token_id: uuid.UUID


class CanaryAuthenticator:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._tokens = TokenHasher(settings)

    async def authenticate(self, raw_token: str) -> AuthenticatedCanary:
        candidates = self._tokens.candidates("canary", raw_token)
        predicate = or_(
            *(
                and_(CanaryAuthToken.key_id == key_id, CanaryAuthToken.token_hash == digest)
                for key_id, digest in candidates
            )
        )
        async with self._sessions() as session:
            now = await _database_now(session)
            tokens = list((await session.scalars(select(CanaryAuthToken).where(predicate))).all())
            valid = [
                token
                for token in tokens
                if token.status in (AuthTokenStatus.CURRENT.value, AuthTokenStatus.NEXT.value)
                and (token.expires_at is None or token.expires_at > now)
            ]
            if len(valid) != 1:
                raise _invalid_canary_token()
            canary = await session.get(Canary, valid[0].canary_id)
            if canary is None or canary.status != "active":
                raise _invalid_canary_token()
            return AuthenticatedCanary(canary_id=canary.id, token_id=valid[0].id)


class CanaryReportService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings

    async def process(
        self,
        identity: AuthenticatedCanary,
        *,
        requested_canary_id: uuid.UUID,
        payload: CanaryRunRequest,
    ) -> dict[str, object]:
        if identity.canary_id != requested_canary_id:
            raise ApplicationError(
                403,
                "CANARY_TOKEN_MISMATCH",
                "Canary token does not match the requested canary",
            )
        request_hash = _request_hash(payload)
        blocked_any = False
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            checked_at = payload.checked_at.astimezone(UTC)
            if checked_at < now - timedelta(minutes=5) or checked_at > now + timedelta(minutes=1):
                raise ApplicationError(400, "INVALID_CHECK_TIME", "Canary check time is invalid")
            existing = await session.get(CanaryRun, payload.run_id)
            if existing is not None:
                if (
                    existing.canary_id != identity.canary_id
                    or existing.request_hash != request_hash
                ):
                    raise ApplicationError(
                        409, "CHECK_ID_CONFLICT", "Canary run ID is already used"
                    )
                return {**existing.response_json, "processed": False}

            expected_targets = {
                url.host for url in self._settings.canary_probe_urls_json if url.host is not None
            }
            submitted_targets = {target.target for item in payload.nodes for target in item.targets}
            if submitted_targets != expected_targets or any(
                {target.target for target in item.targets} != expected_targets
                for item in payload.nodes
            ):
                raise ApplicationError(
                    400,
                    "CANARY_TARGET_MISMATCH",
                    "Canary targets do not match configured probes",
                )
            usable_targets = {
                target.target for item in payload.nodes for target in item.targets if target.success
            }
            outcomes: list[dict[str, object]] = []
            for item in payload.nodes:
                node = (
                    await session.execute(
                        select(Node).where(Node.id == item.node_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if node is None:
                    raise ApplicationError(404, "NODE_NOT_FOUND", "Canary node does not exist")
                existing_check = await session.scalar(
                    select(NodeCheckEvent.id).where(NodeCheckEvent.check_id == item.check_id)
                )
                if existing_check is not None:
                    raise ApplicationError(
                        409, "CHECK_ID_CONFLICT", "Canary check ID is already used"
                    )

                if node.status not in {NodeStatus.ACTIVE.value, NodeStatus.BLOCKED.value}:
                    outcome = "ignored"
                elif not usable_targets:
                    outcome = "inconclusive"
                else:
                    successes = sum(
                        target.success and target.target in usable_targets
                        for target in item.targets
                    )
                    outcome = (
                        "healthy"
                        if successes >= self._settings.canary_min_successful_targets
                        else "failed"
                    )
                if outcome == "healthy":
                    node.failed_checks = 0
                    node.successful_checks += 1
                    if (
                        node.status == NodeStatus.BLOCKED.value
                        and node.successful_checks >= self._settings.node_recovery_success_threshold
                        and not node.recovery_ready
                    ):
                        node.recovery_ready = True
                        await enqueue_admin_alert(
                            session,
                            event_name="node_recovery_ready",
                            idempotency_key=f"admin-alert:node-recovery-ready:{node.id}:{payload.run_id}",
                            aggregate_id=node.id,
                            data={"node_id": str(node.id), "node_name": node.name},
                            now=now,
                        )
                elif outcome == "failed":
                    node.successful_checks = 0
                    node.failed_checks += 1
                    if (
                        node.status == NodeStatus.ACTIVE.value
                        and node.failed_checks >= self._settings.node_block_failure_threshold
                    ):
                        node.status = NodeStatus.BLOCKED.value
                        node.recovery_ready = False
                        blocked_any = True
                        await enqueue_admin_alert(
                            session,
                            event_name="node_blocked",
                            idempotency_key=f"admin-alert:node-blocked:canary:{node.id}:{payload.run_id}",
                            aggregate_id=node.id,
                            data={
                                "node_id": str(node.id),
                                "node_name": node.name,
                                "reason": "canary_connect_failed",
                            },
                            now=now,
                        )
                node.last_check_at = checked_at
                event_response = {
                    "outcome": outcome,
                    "targets": [target.model_dump(mode="json") for target in item.targets],
                    "run_id": str(payload.run_id),
                }
                session.add(
                    NodeCheckEvent(
                        id=uuid.uuid4(),
                        check_id=item.check_id,
                        node_id=node.id,
                        canary_id=identity.canary_id,
                        request_hash=_item_hash(item),
                        response_json=event_response,
                        checked_at=checked_at,
                        created_at=now,
                    )
                )
                outcomes.append(
                    {
                        "node_id": str(node.id),
                        "outcome": outcome,
                        "status": node.status,
                        "failed_checks": node.failed_checks,
                        "successful_checks": node.successful_checks,
                        "recovery_ready": node.recovery_ready,
                    }
                )
            previous_runs = list(
                (
                    await session.scalars(
                        select(CanaryRun)
                        .where(CanaryRun.canary_id == identity.canary_id)
                        .order_by(CanaryRun.checked_at.desc())
                        .limit(self._settings.node_block_failure_threshold)
                    )
                ).all()
            )
            await self._process_ingress_alerts(
                session,
                canary_id=identity.canary_id,
                current=payload.ingresses,
                previous_runs=previous_runs,
                run_id=payload.run_id,
                now=now,
            )
            canary = await session.get(Canary, identity.canary_id)
            assert canary is not None
            canary.last_report_at = now
            response: dict[str, object] = {
                "processed": True,
                "run_id": str(payload.run_id),
                "outcomes": outcomes,
                "ingresses": [item.model_dump(mode="json") for item in payload.ingresses],
                "control_urls": await DiscoveryService(
                    self._sessions, self._settings
                ).active_urls_in_session(session),
            }
            session.add(
                CanaryRun(
                    run_id=payload.run_id,
                    canary_id=identity.canary_id,
                    request_hash=request_hash,
                    response_json=response,
                    checked_at=checked_at,
                    received_at=now,
                )
            )

        if blocked_any:
            watchdog = NodeSnapshotWatchdog(self._sessions, self._settings)
            reassigned, without_capacity = await watchdog.reassign_blocked_users()
            if without_capacity:
                async with self._sessions.begin() as session:
                    now = await _database_now(session)
                    await enqueue_admin_alert(
                        session,
                        event_name="capacity_exhausted",
                        idempotency_key=f"admin-alert:capacity:{payload.run_id}",
                        aggregate_id=None,
                        data={
                            "reassigned_users": reassigned,
                            "users_without_capacity": without_capacity,
                        },
                        now=now,
                    )
        return response

    async def _process_ingress_alerts(
        self,
        session: AsyncSession,
        *,
        canary_id: uuid.UUID,
        current: list,
        previous_runs: list[CanaryRun],
        run_id: uuid.UUID,
        now: datetime,
    ) -> None:
        threshold = self._settings.node_block_failure_threshold
        for result in current:
            previous = [
                item
                for run in previous_runs
                for item in run.response_json.get("ingresses", [])
                if item.get("url") == result.url
            ]
            consecutive_failure = not result.success and all(
                not item.get("success") for item in previous[: threshold - 1]
            )
            if consecutive_failure and len(previous) >= threshold - 1:
                alert_bucket = (
                    int(now.timestamp()) // self._settings.operations_alert_cooldown_seconds
                )
                await enqueue_admin_alert(
                    session,
                    event_name="control_ingress_failed",
                    idempotency_key=(
                        "admin-alert:control-ingress-failed:"
                        f"{hashlib.sha256(result.url.encode()).hexdigest()}:"
                        f"{alert_bucket}"
                    ),
                    aggregate_id=canary_id,
                    data={
                        "url": result.url,
                        "error_code": result.error_code,
                        "attempts": threshold,
                    },
                    now=now,
                )
            recovered = result.success and len(previous) >= threshold and all(
                not item.get("success") for item in previous[:threshold]
            )
            if recovered:
                url_hash = hashlib.sha256(result.url.encode()).hexdigest()
                await enqueue_admin_alert(
                    session,
                    event_name="control_ingress_recovered",
                    idempotency_key=f"admin-alert:control-ingress-recovered:{url_hash}:{run_id}",
                    aggregate_id=canary_id,
                    data={"url": result.url},
                    now=now,
                )


def _request_hash(payload: CanaryRunRequest) -> str:
    canonical = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _item_hash(item: CanaryNodeResult) -> str:
    canonical = json.dumps(
        item.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)


def _invalid_canary_token() -> ApplicationError:
    return ApplicationError(
        401,
        "INVALID_CANARY_TOKEN",
        "Canary token is invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )
