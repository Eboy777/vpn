from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from vpn_service.domain.enums import NodeStatus, UserStatus
from vpn_service.persistence.models import Node, User


async def lock_active_nodes(session: AsyncSession) -> list[Node]:
    """Lock assignment candidates in a stable order.

    Every code path that changes an assignment uses this lock order. This serializes the
    small MVP node pool and prevents concurrent requests from exceeding hard capacity.
    """

    return list(
        (
            await session.scalars(
                select(Node)
                .where(Node.status == NodeStatus.ACTIVE.value)
                .order_by(Node.id)
                .with_for_update()
            )
        ).all()
    )


async def active_node_loads(
    session: AsyncSession,
    *,
    now: datetime,
) -> dict[uuid.UUID, int]:
    rows = (
        await session.execute(
            select(User.assigned_node_id, func.count(User.id))
            .where(
                User.status == UserStatus.ACTIVE.value,
                User.assigned_node_id.is_not(None),
                or_(
                    User.trial_expires_at > now,
                    User.subscription_expires_at > now,
                ),
            )
            .group_by(User.assigned_node_id)
        )
    ).all()
    return {node_id: int(count) for node_id, count in rows if node_id is not None}


async def choose_node(
    session: AsyncSession,
    *,
    now: datetime,
    hard_capacity: bool,
) -> Node | None:
    nodes = await lock_active_nodes(session)
    if not nodes:
        return None
    loads = await active_node_loads(session, now=now)
    eligible = (
        [node for node in nodes if loads.get(node.id, 0) < node.capacity_users]
        if hard_capacity
        else nodes
    )
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda node: (loads.get(node.id, 0) / node.capacity_users, node.id),
    )
