from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NodeObserverSettings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    control_api_base_url: AnyHttpUrl
    control_api_fallback_urls_json: list[AnyHttpUrl] = Field(default_factory=list)
    node_id: uuid.UUID
    node_credentials_token: SecretStr
    node_observer_bind_host: str = "127.0.0.1"
    node_observer_bind_port: Annotated[int, Field(ge=1024, le=65535)] = 9001
    node_observer_report_interval_seconds: Annotated[int, Field(ge=5, le=300)] = 15
    node_observer_http_timeout_seconds: Annotated[float, Field(gt=1, le=60)] = 10
    node_tls_cert_path: Path = Path("/etc/gost/tls/fullchain.pem")
    node_metrics_disk_path: Path = Path("/")
    gost_account_limits_path: Path = Path("/var/lib/vpn-node/account-limits.json")

    @model_validator(mode="after")
    def validate_observer(self) -> NodeObserverSettings:
        token = self.node_credentials_token.get_secret_value()
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            raise ValueError("NODE_CREDENTIALS_TOKEN must be a 43-character token")
        urls = self.control_urls
        if len(urls) != len(set(urls)):
            raise ValueError("control API URLs must be unique")
        if self.node_observer_bind_host not in {"127.0.0.1", "::1"}:
            raise ValueError("node observer must listen on loopback")
        return self

    @property
    def control_urls(self) -> list[str]:
        return [
            str(url).rstrip("/")
            for url in [self.control_api_base_url, *self.control_api_fallback_urls_json]
        ]
