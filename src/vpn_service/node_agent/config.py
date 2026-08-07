from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NodeAgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env.node",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    control_api_base_url: AnyHttpUrl
    control_api_fallback_urls_json: list[AnyHttpUrl] = Field(default_factory=list)
    node_id: uuid.UUID
    node_credentials_token: SecretStr
    node_sync_interval_seconds: Annotated[float, Field(gt=0)] = 30
    node_sync_timeout_seconds: Annotated[float, Field(gt=0)] = 15
    node_sync_jitter_seconds: Annotated[float, Field(ge=0)] = 5
    node_stale_snapshot_policy: Literal["fail_closed"] = "fail_closed"
    node_sync_state_path: Path
    gost_config_path: Path
    gost_config_staging_path: Path
    gost_canary_proxy_username: str
    gost_canary_proxy_password: SecretStr
    gost_canary_credential_version: str
    gost_reload_timeout_seconds: Annotated[float, Field(gt=0)] = 15

    @model_validator(mode="after")
    def validate_agent_profile(self) -> Self:
        urls = [
            str(url).rstrip("/")
            for url in [self.control_api_base_url, *self.control_api_fallback_urls_json]
        ]
        if len(urls) != len(set(urls)):
            raise ValueError("control API URLs must be unique")
        if any(not url.startswith("https://") for url in urls):
            raise ValueError("node control API URLs must use HTTPS")
        if not re.fullmatch(
            r"[A-Za-z0-9_-]{43}",
            self.node_credentials_token.get_secret_value(),
        ):
            raise ValueError("NODE_CREDENTIALS_TOKEN must be a 43-character token")
        username_pattern = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
        password_pattern = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
        if not username_pattern.fullmatch(self.gost_canary_proxy_username):
            raise ValueError("GOST canary username contains unsafe characters")
        if not password_pattern.fullmatch(self.gost_canary_proxy_password.get_secret_value()):
            raise ValueError("GOST canary password contains unsafe characters")
        for name, path in (
            ("NODE_SYNC_STATE_PATH", self.node_sync_state_path),
            ("GOST_CONFIG_PATH", self.gost_config_path),
            ("GOST_CONFIG_STAGING_PATH", self.gost_config_staging_path),
        ):
            if not path.is_absolute():
                raise ValueError(f"{name} must be an absolute path")
        if self.gost_config_path == self.gost_config_staging_path:
            raise ValueError("GOST staging and active paths must differ")
        return self

    @property
    def control_urls(self) -> tuple[str, ...]:
        return tuple(
            str(url).rstrip("/")
            for url in [self.control_api_base_url, *self.control_api_fallback_urls_json]
        )
