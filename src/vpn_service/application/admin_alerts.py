from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vpn_service.domain.enums import OutboxStatus
from vpn_service.persistence.models import OutboxEvent


async def enqueue_admin_alert(
    session: AsyncSession,
    *,
    event_name: str,
    idempotency_key: str,
    aggregate_id: uuid.UUID | None,
    data: dict[str, Any],
    now: datetime,
) -> None:
    await session.execute(
        insert(OutboxEvent)
        .values(
            id=uuid.uuid4(),
            event_type="admin.telegram.alert",
            aggregate_type="operations",
            aggregate_id=aggregate_id,
            idempotency_key=idempotency_key,
            payload_json={"event": event_name, "data": data},
            status=OutboxStatus.PENDING.value,
            attempts=0,
            available_at=now,
        )
        .on_conflict_do_nothing(index_elements=[OutboxEvent.idempotency_key])
    )
