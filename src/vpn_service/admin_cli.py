from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from datetime import UTC

from sqlalchemy import func, or_, select

from vpn_service.application.node_assignment import choose_node
from vpn_service.config import Settings
from vpn_service.domain.enums import AuthTokenStatus, NodeStatus
from vpn_service.persistence.database import Database
from vpn_service.persistence.models import Node, NodeAuthToken, User
from vpn_service.security.tokens import TokenHasher


async def run(args: argparse.Namespace) -> dict[str, object]:
    settings = Settings()  # type: ignore[call-arg]
    database = Database(settings)
    try:
        if args.command == "node-add":
            return await _add_node(database, args)
        if args.command == "node-token-issue":
            return await _issue_node_token(database, settings, args)
        if args.command == "node-token-promote":
            return await _promote_node_token(database, args)
        if args.command == "node-token-revoke":
            return await _revoke_node_token(database, args)
        if args.command == "node-activate":
            return await _activate_node(database, args)
        if args.command == "node-drain-prepare":
            return await _prepare_node_drain(database, settings, args)
        if args.command == "node-drain-finalize":
            return await _finalize_node_drain(database, args)
        raise RuntimeError("unsupported admin command")
    finally:
        await database.dispose()


async def _add_node(database: Database, args: argparse.Namespace) -> dict[str, object]:
    node_id = uuid.uuid4()
    async with database.sessions.begin() as session:
        session.add(
            Node(
                id=node_id,
                name=args.name,
                host=args.host,
                port=args.port,
                country_code=args.country_code,
                provider=args.provider,
                status=NodeStatus.WARMING.value,
                capacity_users=args.capacity_users,
            )
        )
    return {"node_id": str(node_id), "status": NodeStatus.WARMING.value}


async def _issue_node_token(
    database: Database,
    settings: Settings,
    args: argparse.Namespace,
) -> dict[str, object]:
    node_id = uuid.UUID(args.node_id)
    async with database.sessions.begin() as session:
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None:
            raise RuntimeError("node not found")
        accepted = list(
            (
                await session.scalars(
                    select(NodeAuthToken).where(
                        NodeAuthToken.node_id == node_id,
                        NodeAuthToken.status.in_(
                            [AuthTokenStatus.CURRENT.value, AuthTokenStatus.NEXT.value]
                        ),
                    )
                )
            ).all()
        )
        desired_status = args.status
        if any(token.status == desired_status for token in accepted):
            raise RuntimeError(f"node already has a {desired_status} token")
        if desired_status == AuthTokenStatus.CURRENT.value and accepted:
            raise RuntimeError("bootstrap current token is allowed only before rotation starts")
        issued = TokenHasher(settings).issue("node")
        token_id = uuid.uuid4()
        session.add(
            NodeAuthToken(
                id=token_id,
                node_id=node_id,
                key_id=issued.key_id,
                token_hash=issued.digest,
                status=desired_status,
            )
        )
    return {
        "node_id": str(node_id),
        "token_id": str(token_id),
        "status": desired_status,
        "node_credentials_token": issued.raw,
        "warning": "Store this token now; it cannot be recovered from the database.",
    }


async def _promote_node_token(database: Database, args: argparse.Namespace) -> dict[str, object]:
    node_id = uuid.UUID(args.node_id)
    token_id = uuid.UUID(args.token_id)
    async with database.sessions.begin() as session:
        await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        tokens = list(
            (
                await session.scalars(
                    select(NodeAuthToken)
                    .where(NodeAuthToken.node_id == node_id)
                    .order_by(NodeAuthToken.id)
                    .with_for_update()
                )
            ).all()
        )
        selected = next((token for token in tokens if token.id == token_id), None)
        now = await session.scalar(select(func.now()))
        assert now is not None
        now = now.astimezone(UTC)
        if (
            selected is None
            or selected.status != AuthTokenStatus.NEXT.value
            or (selected.expires_at is not None and selected.expires_at <= now)
        ):
            raise RuntimeError("promoted token must be a non-expired next token of this node")
        for token in tokens:
            if token.status == AuthTokenStatus.CURRENT.value:
                token.status = AuthTokenStatus.REVOKED.value
        selected.status = AuthTokenStatus.CURRENT.value
    return {"node_id": str(node_id), "token_id": str(token_id), "status": "current"}


async def _revoke_node_token(database: Database, args: argparse.Namespace) -> dict[str, object]:
    node_id = uuid.UUID(args.node_id)
    token_id = uuid.UUID(args.token_id)
    async with database.sessions.begin() as session:
        token = (
            await session.execute(
                select(NodeAuthToken)
                .where(NodeAuthToken.node_id == node_id, NodeAuthToken.id == token_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if token is None:
            raise RuntimeError("node token not found")
        token.status = AuthTokenStatus.REVOKED.value
    return {"node_id": str(node_id), "token_id": str(token_id), "status": "revoked"}


async def _activate_node(database: Database, args: argparse.Namespace) -> dict[str, object]:
    node_id = uuid.UUID(args.node_id)
    async with database.sessions.begin() as session:
        now = await session.scalar(select(func.now()))
        assert now is not None
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None:
            raise RuntimeError("node not found")
        current_token = await session.scalar(
            select(NodeAuthToken.id).where(
                NodeAuthToken.node_id == node_id,
                NodeAuthToken.status == AuthTokenStatus.CURRENT.value,
                (NodeAuthToken.expires_at.is_(None) | (NodeAuthToken.expires_at > now)),
            )
        )
        if (
            node.status != NodeStatus.WARMING.value
            or current_token is None
            or node.credentials_revision is None
            or node.applied_credentials_revision != node.credentials_revision
            or node.applied_snapshot_valid_until is None
            or node.applied_snapshot_valid_until <= now
        ):
            raise RuntimeError("warming node requires a current token and fresh applied snapshot")
        node.status = NodeStatus.ACTIVE.value
    return {"node_id": str(node_id), "status": NodeStatus.ACTIVE.value}


async def _prepare_node_drain(
    database: Database,
    settings: Settings,
    args: argparse.Namespace,
) -> dict[str, object]:
    node_id = uuid.UUID(args.node_id)
    async with database.sessions.begin() as session:
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None or node.status not in (
            NodeStatus.ACTIVE.value,
            NodeStatus.QUIESCING.value,
        ):
            raise RuntimeError("only an active or quiescing node can be prepared for drain")
        node.status = NodeStatus.QUIESCING.value

    reassigned = 0
    without_capacity = 0
    async with database.sessions() as lookup:
        user_ids = list(
            (
                await lookup.scalars(
                    select(User.id).where(User.assigned_node_id == node_id).order_by(User.id)
                )
            ).all()
        )
    for user_id in user_ids:
        async with database.sessions.begin() as session:
            user = (
                await session.execute(select(User).where(User.id == user_id).with_for_update())
            ).scalar_one_or_none()
            if user is None or user.assigned_node_id != node_id:
                continue
            now = await session.scalar(select(func.now()))
            assert now is not None
            selected = await choose_node(
                session,
                now=now.astimezone(UTC),
                hard_capacity=settings.node_assignment_hard_capacity,
            )
            if selected is None:
                without_capacity += 1
            else:
                user.assigned_node_id = selected.id
                user.node_selection_mode = "auto"
                reassigned += 1
    return {
        "node_id": str(node_id),
        "status": NodeStatus.QUIESCING.value,
        "reassigned_users": reassigned,
        "users_without_capacity": without_capacity,
    }


async def _finalize_node_drain(database: Database, args: argparse.Namespace) -> dict[str, object]:
    node_id = uuid.UUID(args.node_id)
    async with database.sessions.begin() as session:
        node = (
            await session.execute(select(Node).where(Node.id == node_id).with_for_update())
        ).scalar_one_or_none()
        if node is None or node.status != NodeStatus.QUIESCING.value:
            raise RuntimeError("only a quiescing node can enter draining")
        now = await session.scalar(select(func.now()))
        assert now is not None
        remaining = await session.scalar(
            select(func.count(User.id)).where(
                User.assigned_node_id == node_id,
                User.status == "active",
                or_(User.trial_expires_at > now, User.subscription_expires_at > now),
            )
        )
        if remaining:
            raise RuntimeError("active users are still assigned to the quiescing node")
        node.status = NodeStatus.DRAINING.value
    return {"node_id": str(node_id), "status": NodeStatus.DRAINING.value}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vpn-admin")
    commands = result.add_subparsers(dest="command", required=True)

    add = commands.add_parser("node-add")
    add.add_argument("--name", required=True)
    add.add_argument("--host", required=True)
    add.add_argument("--port", type=int, required=True)
    add.add_argument("--country-code", required=True)
    add.add_argument("--provider", required=True)
    add.add_argument("--capacity-users", type=int, required=True)

    activate = commands.add_parser("node-activate")
    activate.add_argument("--node-id", required=True)

    for command in ("node-drain-prepare", "node-drain-finalize"):
        drain = commands.add_parser(command)
        drain.add_argument("--node-id", required=True)

    issue = commands.add_parser("node-token-issue")
    issue.add_argument("--node-id", required=True)
    issue.add_argument(
        "--status",
        choices=[AuthTokenStatus.CURRENT.value, AuthTokenStatus.NEXT.value],
        required=True,
    )

    for command in ("node-token-promote", "node-token-revoke"):
        token_command = commands.add_parser(command)
        token_command.add_argument("--node-id", required=True)
        token_command.add_argument("--token-id", required=True)
    return result


def main() -> None:
    result = asyncio.run(run(parser().parse_args()))
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
