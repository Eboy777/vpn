from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


SignedInt64 = Annotated[int, Field(strict=True, ge=-(2**63), le=2**63 - 1)]
NonNegativeInt64 = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class TelegramUser(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: SignedInt64
    is_bot: Literal[False]
    first_name: Annotated[str, Field(min_length=1)]


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
    from_user: TelegramUser = Field(alias="from")
    chat: TelegramChat
    text: Annotated[str, Field(min_length=1, max_length=4096)]
    entities: Annotated[list[TelegramEntity], Field(min_length=1)]


class TelegramUpdateRequest(StrictRequest):
    update_id: NonNegativeInt64
    message: TelegramMessage
