from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.enums import AuthTokenStatus, NodeStatus, UserStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.persistence.models import (
    Node,
    NodeAuthToken,
    NodeSnapshotAck,
    NodeSnapshotIssue,
    User,
)
from vpn_service.persistence.rate_limits import consume_rate_limit
from vpn_service.security.credentials import ProxyCredentialsCipher
from vpn_service.security.tokens import TokenHasher


@dataclass(frozen=True, slots=True)
class AuthenticatedNode:
    node_id: uuid.UUID
    token_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class SnapshotCredential:
    proxy_username: str
    proxy_password: str
    valid_until: str


@dataclass(frozen=True, slots=True)
class SnapshotResult:
    node_id: uuid.UUID
    node_status: str
    generated_at: str
    snapshot_valid_until: str
    revision: str
    credentials: tuple[SnapshotCredential, ...]
    not_modified: bool


@dataclass(frozen=True, slots=True)
class AckResult:
    response: dict[str, object]


class NodeAuthenticator:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._tokens = TokenHasher(settings)

    async def authenticate(self, raw_token: str) -> AuthenticatedNode:
        candidates = self._tokens.candidates("node", raw_token)
        predicate = or_(
            *(
                and_(NodeAuthToken.key_id == key_id, NodeAuthToken.token_hash == digest)
                for key_id, digest in candidates
            )
        )
        async with self._sessions() as session:
            now = await _database_now(session)
            matches = list((await session.scalars(select(NodeAuthToken).where(predicate))).all())
            valid = [
                token
                for token in matches
                if token.status in (AuthTokenStatus.CURRENT.value, AuthTokenStatus.NEXT.value)
                and (token.expires_at is None or token.expires_at > now)
            ]
            if not valid or len({token.node_id for token in valid}) != 1:
                raise _invalid_node_token()
            token = valid[0]
            return AuthenticatedNode(node_id=token.node_id, token_id=token.id)


class NodeCredentialsService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._credentials = ProxyCredentialsCipher(settings)
        self._tokens = TokenHasher(settings)

    async def snapshot(
        self,
        identity: AuthenticatedNode,
        *,
        requested_node_id: uuid.UUID,
        if_none_match: str | None,
    ) -> SnapshotResult:
        self._require_matching_node(identity, requested_node_id)
        await self._enforce_rate_limit(identity.node_id)
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            node = await _locked_node(session, requested_node_id)
            if node.status == NodeStatus.DEAD.value:
                raise ApplicationError(409, "NODE_DEAD", "Node is dead")

            credentials: list[SnapshotCredential] = []
            snapshot_with_users = (
                NodeStatus.WARMING.value,
                NodeStatus.ACTIVE.value,
                NodeStatus.QUIESCING.value,
            )
            if node.status in snapshot_with_users:
                users = list(
                    (
                        await session.scalars(
                            select(User)
                            .where(
                                User.status == UserStatus.ACTIVE.value,
                                or_(
                                    User.trial_expires_at > now,
                                    User.subscription_expires_at > now,
                                ),
                            )
                            .order_by(User.proxy_username)
                        )
                    ).all()
                )
                try:
                    credentials = [self._snapshot_credential(user, now) for user in users]
                except (ValueError, UnicodeError) as exc:
                    raise ApplicationError(
                        503,
                        "SERVICE_UNAVAILABLE",
                        "Credentials are unavailable",
                    ) from exc

            revision = _revision(node.status, credentials)
            valid_until = now + timedelta(
                seconds=self._settings.node_credential_snapshot_ttl_seconds
            )
            await session.execute(
                insert(NodeSnapshotIssue)
                .values(
                    node_id=node.id,
                    revision=revision,
                    snapshot_valid_until=valid_until,
                    issued_at=now,
                )
                .on_conflict_do_update(
                    constraint="uq_node_snapshot_issue_revision",
                    set_={
                        "snapshot_valid_until": valid_until,
                        "issued_at": now,
                    },
                )
            )
            node.credentials_revision = revision
            node.snapshot_valid_until = valid_until
            return SnapshotResult(
                node_id=node.id,
                node_status=node.status,
                generated_at=_format_datetime(now),
                snapshot_valid_until=_format_datetime(valid_until),
                revision=revision,
                credentials=tuple(credentials),
                not_modified=(
                    node.status in snapshot_with_users and if_none_match == f'"sha256:{revision}"'
                ),
            )

    async def acknowledge(
        self,
        identity: AuthenticatedNode,
        *,
        requested_node_id: uuid.UUID,
        revision: str,
    ) -> AckResult:
        self._require_matching_node(identity, requested_node_id)
        await self._enforce_rate_limit(identity.node_id)
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            node = await _locked_node(session, requested_node_id)
            if node.status == NodeStatus.DEAD.value:
                raise ApplicationError(409, "NODE_DEAD", "Node is dead")
            existing = (
                await session.execute(
                    select(NodeSnapshotAck).where(
                        NodeSnapshotAck.node_id == node.id,
                        NodeSnapshotAck.revision == revision,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                return AckResult(response=_normalized_ack_response(existing.response_json))

            issue = (
                await session.execute(
                    select(NodeSnapshotIssue).where(
                        NodeSnapshotIssue.node_id == node.id,
                        NodeSnapshotIssue.revision == revision,
                    )
                )
            ).scalar_one_or_none()
            if issue is None:
                raise ApplicationError(
                    409,
                    "SNAPSHOT_REVISION_UNKNOWN",
                    "Snapshot revision was not issued",
                )
            if issue.snapshot_valid_until <= now:
                raise ApplicationError(
                    409,
                    "SNAPSHOT_LEASE_EXPIRED",
                    "Snapshot lease has expired",
                )

            response: dict[str, object] = {
                "processed": True,
                "node_id": str(node.id),
                "revision": revision,
                "applied_at": _format_datetime(now),
            }
            session.add(
                NodeSnapshotAck(
                    node_id=node.id,
                    revision=revision,
                    applied_at=now,
                    response_json=response,
                )
            )
            node.applied_credentials_revision = revision
            node.last_sync_at = now
            return AckResult(response=response)

    def _snapshot_credential(self, user: User, now: datetime) -> SnapshotCredential:
        expiries = [
            expiry
            for expiry in (user.trial_expires_at, user.subscription_expires_at)
            if expiry is not None and expiry > now
        ]
        valid_until = max(expiries)
        return SnapshotCredential(
            proxy_username=user.proxy_username,
            proxy_password=self._credentials.decrypt(user.id, user.proxy_password_ciphertext),
            valid_until=_format_datetime(valid_until),
        )

    async def _enforce_rate_limit(self, node_id: uuid.UUID) -> None:
        scope = "internal-node-minute"
        subject = self._tokens.opaque_subject(scope, str(node_id))
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            decision = await consume_rate_limit(
                session,
                scope=scope,
                subject_hash=subject,
                limit=self._settings.internal_api_rate_per_minute,
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

    @staticmethod
    def _require_matching_node(
        identity: AuthenticatedNode,
        requested_node_id: uuid.UUID,
    ) -> None:
        if identity.node_id != requested_node_id:
            raise ApplicationError(
                403,
                "NODE_TOKEN_MISMATCH",
                "Node token does not match the requested node",
            )


async def _database_now(session: AsyncSession) -> datetime:
    now = await session.scalar(select(func.now()))
    assert now is not None
    return now.astimezone(UTC)


async def _locked_node(session: AsyncSession, node_id: uuid.UUID) -> Node:
    node = (
        await session.execute(select(Node).where(Node.id == node_id).with_for_update())
    ).scalar_one_or_none()
    if node is None:
        raise _invalid_node_token()
    return node


def _revision(status: str, credentials: list[SnapshotCredential]) -> str:
    canonical = {
        "node_status": status,
        "credentials": [
            {
                "proxy_username": credential.proxy_username,
                "proxy_password": credential.proxy_password,
                "valid_until": credential.valid_until,
            }
            for credential in credentials
        ],
    }
    payload = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _invalid_node_token() -> ApplicationError:
    return ApplicationError(
        401,
        "INVALID_NODE_TOKEN",
        "Node token is invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _normalized_ack_response(stored: dict[str, object]) -> dict[str, object]:
    return {
        "processed": stored["processed"],
        "node_id": stored["node_id"],
        "revision": stored["revision"],
        "applied_at": stored["applied_at"],
    }
