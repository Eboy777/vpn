from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vpn_service.persistence.models import RateLimitCounter


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


async def consume_rate_limit(
    session: AsyncSession,
    *,
    scope: str,
    subject_hash: bytes,
    limit: int,
    window_seconds: int,
    now: datetime,
) -> RateLimitDecision:
    window_start = _window_start(now, window_seconds)
    statement = insert(RateLimitCounter).values(
        scope=scope,
        subject_hash=subject_hash,
        window_start=window_start,
        request_count=1,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[
            RateLimitCounter.scope,
            RateLimitCounter.subject_hash,
            RateLimitCounter.window_start,
        ],
        set_={"request_count": RateLimitCounter.request_count + 1},
    ).returning(RateLimitCounter.request_count)
    count = int((await session.execute(statement)).scalar_one())
    window_end = window_start + timedelta(seconds=window_seconds)
    retry_after = max(1, math.ceil((window_end - now).total_seconds()))
    return RateLimitDecision(
        allowed=count <= limit,
        limit=limit,
        remaining=max(0, limit - count),
        retry_after=retry_after,
    )


def _window_start(now: datetime, window_seconds: int) -> datetime:
    normalized = now.astimezone(UTC)
    epoch = int(normalized.timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, tz=UTC)
