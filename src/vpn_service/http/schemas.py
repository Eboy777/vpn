from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator


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


class ExtensionLifecycleRequest(StrictRequest):
    event_id: uuid.UUID
    installation_id: uuid.UUID
    event_type: Literal["installed", "launched", "updated"]
    extension_version: Annotated[str, Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$")]


class DeviceTelemetryRequest(StrictRequest):
    event_id: uuid.UUID
    event_type: Literal["vpn_started", "vpn_heartbeat", "vpn_stopped", "connection_error"]
    session_id: uuid.UUID
    extension_version: Annotated[str, Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$")]
    error_code: Annotated[str, Field(pattern=r"^[A-Z0-9_]{1,64}$")] | None = None

    @model_validator(mode="after")
    def error_code_matches_event(self) -> DeviceTelemetryRequest:
        if (self.event_type == "connection_error") != (self.error_code is not None):
            raise ValueError("error_code is required only for connection_error")
        return self


class TelemetryAcceptedResponse(StrictRequest):
    processed: bool


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


class NodeTrafficClientMetric(StrictRequest):
    proxy_username: Annotated[str, Field(pattern=r"^u_[a-z0-9]{26}$")]
    total_connections: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    current_connections: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    input_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    output_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    total_errors: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    connection_seconds: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class NodeRuntimeMetricRequest(StrictRequest):
    cpu_percent: Annotated[float, Field(ge=0, le=100)]
    memory_percent: Annotated[float, Field(ge=0, le=100)]
    disk_percent: Annotated[float, Field(ge=0, le=100)]
    network_rx_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    network_tx_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    gost_up: bool
    sync_agent_up: bool
    tls_expires_at: AwareDatetime | None = None


class NodeTelemetryRequest(StrictRequest):
    report_id: uuid.UUID
    observed_at: AwareDatetime
    clients: Annotated[list[NodeTrafficClientMetric], Field(max_length=10_000)]
    runtime: NodeRuntimeMetricRequest


class NodeTelemetryResponse(StrictRequest):
    processed: bool
    node_id: uuid.UUID
    report_id: uuid.UUID
    accepted_clients: Annotated[int, Field(ge=0)]


class CanaryTargetResult(StrictRequest):
    target: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")]
    success: bool
    latency_ms: Annotated[float, Field(ge=0, le=300_000)] | None = None
    status_code: Annotated[int, Field(ge=100, le=599)] | None = None
    error_code: Annotated[str, Field(pattern=r"^[A-Z0-9_]{1,64}$")] | None = None

    @model_validator(mode="after")
    def result_fields_match_success(self) -> CanaryTargetResult:
        if self.success and (self.latency_ms is None or self.error_code is not None):
            raise ValueError("successful target requires latency and no error")
        if not self.success and self.error_code is None:
            raise ValueError("failed target requires error_code")
        return self


class CanaryNodeResult(StrictRequest):
    check_id: uuid.UUID
    node_id: uuid.UUID
    targets: Annotated[list[CanaryTargetResult], Field(min_length=2, max_length=10)]

    @model_validator(mode="after")
    def unique_targets(self) -> CanaryNodeResult:
        if len({target.target for target in self.targets}) != len(self.targets):
            raise ValueError("canary targets must be unique per node")
        return self


class CanaryRunRequest(StrictRequest):
    run_id: uuid.UUID
    checked_at: AwareDatetime
    nodes: Annotated[list[CanaryNodeResult], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def unique_node_results(self) -> CanaryRunRequest:
        if len({item.node_id for item in self.nodes}) != len(self.nodes):
            raise ValueError("canary node results must be unique")
        if len({item.check_id for item in self.nodes}) != len(self.nodes):
            raise ValueError("canary check IDs must be unique")
        return self


class CanaryNodeOutcome(StrictRequest):
    node_id: uuid.UUID
    outcome: Literal["healthy", "failed", "inconclusive", "ignored"]
    status: Literal["warming", "active", "quiescing", "draining", "dead", "blocked"]
    failed_checks: Annotated[int, Field(ge=0)]
    successful_checks: Annotated[int, Field(ge=0)]
    recovery_ready: bool


class CanaryRunResponse(StrictRequest):
    processed: bool
    run_id: uuid.UUID
    outcomes: list[CanaryNodeOutcome]


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
