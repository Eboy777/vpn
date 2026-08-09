from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PairingInitRequest(StrictRequest):
    device_id: uuid.UUID

    @field_validator("device_id", mode="before")
    @classmethod
    def canonical_device_id(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("device_id must be a canonical UUID string")
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise ValueError("device_id must be a canonical UUID string") from exc
        if str(parsed) != value:
            raise ValueError("device_id must be a canonical lowercase UUID")
        return value


class PairingInitResponse(StrictRequest):
    device_id: uuid.UUID
    pairing_session_token: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    telegram_url: str
    expires_at: datetime
    poll_after_seconds: Annotated[int, Field(ge=2, le=60)]


class PairingPendingResponse(StrictRequest):
    status: Literal["pending"] = "pending"
    expires_at: datetime
    poll_after_seconds: Annotated[int, Field(ge=2, le=60)]


class PairingPairedResponse(StrictRequest):
    status: Literal["paired"] = "paired"
    device_id: uuid.UUID
    device_token: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    token_type: Literal["Bearer"] = "Bearer"


class PublicNodeResponse(StrictRequest):
    id: uuid.UUID
    name: Annotated[str, Field(min_length=1, max_length=64)]
    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)]
    country_code: Annotated[str, Field(pattern=r"^[A-Z]{2}$")]


class AccessDetailsResponse(StrictRequest):
    state: Literal["trial", "paid", "expired", "blocked"]
    trial_expires_at: datetime | None
    subscription_expires_at: datetime | None
    access_expires_at: datetime | None
    can_select_node: bool


class ProxyCredentialsResponse(StrictRequest):
    proxy_username: Annotated[str, Field(pattern=r"^u_[a-z0-9]{26}$")]
    proxy_password: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{32}$")]


class VpnStatusResponse(StrictRequest):
    available: bool
    unavailable_reason: Literal["ACCESS_EXPIRED", "USER_BLOCKED", "NO_ACTIVE_NODE"] | None
    node: PublicNodeResponse | None
    credentials: ProxyCredentialsResponse | None
    bypass_list: Annotated[list[str], Field(min_length=1, max_length=10)]


class StatusResponse(StrictRequest):
    device_id: uuid.UUID
    access: AccessDetailsResponse
    node_selection_mode: Literal["auto", "manual"]
    vpn: VpnStatusResponse
    server_time: datetime
    next_check_seconds: Annotated[int, Field(ge=60, le=3600)]


class SelectableNodeResponse(StrictRequest):
    id: uuid.UUID
    name: Annotated[str, Field(min_length=1, max_length=64)]
    country_code: Annotated[str, Field(pattern=r"^[A-Z]{2}$")]
    selected: bool


class NodeListResponse(StrictRequest):
    nodes: Annotated[list[SelectableNodeResponse], Field(max_length=100)]
    node_selection_mode: Literal["auto", "manual"]
    generated_at: datetime


class NodeSelectRequest(StrictRequest):
    node_id: uuid.UUID | None

    @field_validator("node_id", mode="before")
    @classmethod
    def canonical_node_id(cls, value: object) -> object:
        if value is None:
            return value
        if not isinstance(value, str):
            raise ValueError("node_id must be null or a canonical UUID string")
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise ValueError("node_id must be null or a canonical UUID string") from exc
        if str(parsed) != value:
            raise ValueError("node_id must be a canonical lowercase UUID")
        return value


class NodeSelectionResponse(StrictRequest):
    assigned_node: PublicNodeResponse
    node_selection_mode: Literal["auto", "manual"]
    changed: bool


class SnapshotCredentialResponse(StrictRequest):
    proxy_username: Annotated[str, Field(pattern=r"^u_[a-z0-9]{26}$")]
    proxy_password: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{32}$")]
    valid_until: datetime


class NodeCredentialsSnapshotResponse(StrictRequest):
    node_id: uuid.UUID
    node_status: Literal["warming", "active", "quiescing", "draining", "blocked"]
    generated_at: datetime
    snapshot_valid_until: datetime
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    credentials: Annotated[list[SnapshotCredentialResponse], Field(max_length=100_000)]


class NodeCredentialsAckRequest(StrictRequest):
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class NodeCredentialsAckResponse(StrictRequest):
    processed: Literal[True]
    node_id: uuid.UUID
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    applied_at: datetime


SignedInt64 = Annotated[int, Field(strict=True, ge=-(2**63), le=2**63 - 1)]
NonNegativeInt64 = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class TelegramActor(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: SignedInt64
    is_bot: bool
    first_name: Annotated[str, Field(min_length=1)]
    username: Annotated[str, Field(min_length=1, max_length=32)] | None = None


class TelegramUser(TelegramActor):
    is_bot: Literal[False]


class TelegramChat(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: SignedInt64
    type: Literal["private"]


class TelegramEntity(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    offset: NonNegativeInt64
    length: NonNegativeInt64


class TelegramMessage(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    message_id: SignedInt64
    date: SignedInt64
    from_user: TelegramActor = Field(alias="from")
    chat: TelegramChat
    text: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    entities: list[TelegramEntity] = Field(default_factory=list)


class TelegramCallbackQuery(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: Annotated[str, Field(min_length=1, max_length=128)]
    from_user: TelegramUser = Field(alias="from")
    message: TelegramMessage | None = None
    data: Annotated[str, Field(min_length=1, max_length=64)] | None = None


class TelegramUpdateRequest(StrictRequest):
    update_id: NonNegativeInt64
    message: TelegramMessage | None = None
    callback_query: TelegramCallbackQuery | None = None

    @model_validator(mode="after")
    def exactly_one_supported_update(self) -> TelegramUpdateRequest:
        if (self.message is None) == (self.callback_query is None):
            raise ValueError("exactly one of message or callback_query is required")
        if self.message is not None and self.message.from_user.is_bot:
            raise ValueError("bot-authored messages are not supported updates")
        return self
