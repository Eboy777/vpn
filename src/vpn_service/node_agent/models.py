from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SnapshotCredential(StrictModel):
    proxy_username: Annotated[str, Field(pattern=r"^u_[a-z0-9]{26}$")]
    proxy_password: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{32}$")]
    valid_until: datetime
    bandwidth_limit_bytes_per_second: Annotated[int, Field(strict=True, ge=0, le=10**10)]


class CredentialsSnapshot(StrictModel):
    node_id: uuid.UUID
    node_status: Literal["warming", "active", "quiescing", "draining", "blocked"]
    generated_at: datetime
    snapshot_valid_until: datetime
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    credentials: Annotated[list[SnapshotCredential], Field(max_length=100_000)]

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        generated = self.generated_at.astimezone(UTC)
        lease = self.snapshot_valid_until.astimezone(UTC)
        if lease <= generated:
            raise ValueError("snapshot lease must be later than generation time")
        usernames = [item.proxy_username for item in self.credentials]
        if usernames != sorted(usernames) or len(usernames) != len(set(usernames)):
            raise ValueError("snapshot credentials must be sorted and unique")
        if self.node_status in ("blocked", "draining") and self.credentials:
            raise ValueError("non-active node snapshot must not contain user credentials")
        if any(item.valid_until.astimezone(UTC) <= generated for item in self.credentials):
            raise ValueError("snapshot contains an expired credential")
        return self


class AgentState(StrictModel):
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    snapshot_valid_until: datetime | None = None
    ack_pending: bool = False
    failed_closed: bool = True


class AckResponse(StrictModel):
    processed: Literal[True]
    node_id: uuid.UUID
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    applied_at: datetime
