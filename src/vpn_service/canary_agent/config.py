from __future__ import annotations

import re
import uuid
from typing import Annotated

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CanaryNodeTarget(BaseModel):
    model_config = {"extra": "forbid"}

    node_id: uuid.UUID
    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)] = 443
    username: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{3,128}$")]
    password: SecretStr

    @model_validator(mode="after")
    def validate_password(self) -> CanaryNodeTarget:
        if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.password.get_secret_value()) is None:
            raise ValueError("canary proxy password has an invalid format")
        return self


class CanaryAgentSettings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    control_api_base_url: AnyHttpUrl
    control_api_fallback_urls_json: list[AnyHttpUrl] = Field(default_factory=list)
    canary_id: uuid.UUID
    canary_token: SecretStr
    canary_nodes_json: Annotated[list[CanaryNodeTarget], Field(min_length=1, max_length=100)]
    canary_probe_urls_json: Annotated[list[AnyHttpUrl], Field(min_length=2, max_length=10)]
    canary_check_interval_seconds: Annotated[int, Field(ge=10, le=300)] = 60
    canary_request_timeout_seconds: Annotated[float, Field(gt=1, le=60)] = 15
    canary_control_failure_alert_after: Annotated[int, Field(ge=2, le=10)] = 3
    canary_admin_telegram_bot_token: SecretStr | None = None
    canary_admin_telegram_chat_ids_json: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_agent(self) -> CanaryAgentSettings:
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", self.canary_token.get_secret_value()) is None:
            raise ValueError("CANARY_TOKEN must be a 43-character token")
        if len({node.node_id for node in self.canary_nodes_json}) != len(self.canary_nodes_json):
            raise ValueError("canary node IDs must be unique")
        if len({url.host for url in self.canary_probe_urls_json}) != len(
            self.canary_probe_urls_json
        ):
            raise ValueError("canary probe hosts must be unique")
        if len(self.control_urls) != len(set(self.control_urls)):
            raise ValueError("control API URLs must be unique")
        if (self.canary_admin_telegram_bot_token is None) != (
            not self.canary_admin_telegram_chat_ids_json
        ):
            raise ValueError(
                "canary admin Telegram token and recipients must be configured together"
            )
        if (
            self.canary_admin_telegram_bot_token is not None
            and len(self.canary_admin_telegram_bot_token.get_secret_value()) < 32
        ):
            raise ValueError("CANARY_ADMIN_TELEGRAM_BOT_TOKEN is too short")
        if any(chat_id == 0 for chat_id in self.canary_admin_telegram_chat_ids_json):
            raise ValueError("canary admin Telegram chat IDs must be non-zero")
        return self

    @property
    def control_urls(self) -> list[str]:
        return [
            str(url).rstrip("/")
            for url in [self.control_api_base_url, *self.control_api_fallback_urls_json]
        ]
