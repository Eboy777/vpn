from __future__ import annotations

import base64
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class ProcessRole(StrEnum):
    API = "api"
    WORKER = "worker"


class LogFormat(StrEnum):
    JSON = "json"
    CONSOLE = "console"


class TariffSettings(BaseModel):
    model_config = {"extra": "forbid"}

    amount_minor: Annotated[int, Field(gt=0)]
    period_days: Annotated[int, Field(gt=0)]
    currency: Literal["RUB"]
    enabled: bool
    description: Annotated[str, Field(min_length=1, max_length=100)]


class Settings(BaseSettings):
    """Typed runtime configuration.

    Production-specific invariants intentionally fail at process startup. Secret values use
    ``SecretStr`` so accidental settings serialization does not expose them.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: AppEnvironment = AppEnvironment.DEVELOPMENT
    app_public_base_url: AnyHttpUrl = AnyHttpUrl("https://api.example.test")
    public_control_urls_json: list[AnyHttpUrl] = Field(
        default_factory=lambda: [
            AnyHttpUrl("https://api-a.example.test"),
            AnyHttpUrl("https://api-b.example.test"),
        ]
    )
    app_bind_host: str = "0.0.0.0"
    app_bind_port: Annotated[int, Field(ge=1, le=65535)] = 8000

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: LogFormat = LogFormat.JSON
    process_role: ProcessRole = ProcessRole.API

    database_url: SecretStr = SecretStr("postgresql+asyncpg://vpn:vpn-local-only@postgres:5432/vpn")
    db_pool_size: Annotated[int, Field(gt=0)] = 10
    db_max_overflow: Annotated[int, Field(ge=0)] = 10
    db_pool_timeout_seconds: Annotated[float, Field(gt=0)] = 10
    db_statement_timeout_ms: Annotated[int, Field(gt=0)] = 10_000

    worker_poll_interval_seconds: Annotated[float, Field(gt=0)] = 1
    outbox_retry_base_seconds: Annotated[int, Field(gt=0)] = 5
    outbox_retry_max_seconds: Annotated[int, Field(gt=0)] = 300
    outbox_max_attempts: Annotated[int, Field(ge=1)] = 10

    token_hash_keyring_json: dict[str, dict[str, SecretStr]]
    token_hash_active_key_ids_json: dict[str, str]
    proxy_credentials_keyring_json: dict[str, SecretStr]
    proxy_credentials_active_key_id: str

    trial_duration_seconds: Annotated[int, Field(gt=0)] = 86_400
    pairing_token_ttl_seconds: Annotated[int, Field(gt=0)] = 600
    device_limit_per_user: Annotated[int, Field(gt=0)] = 3

    telegram_delivery_mode: Literal["webhook", "polling"] = "webhook"
    telegram_bot_token: SecretStr | None = None
    telegram_bot_username: str | None = None
    telegram_webhook_public_base_url: AnyHttpUrl | None = None
    telegram_webhook_secret: SecretStr | None = None
    telegram_webhook_path_secret: SecretStr | None = None

    node_assignment_hard_capacity: bool = True
    node_block_failure_threshold: Annotated[int, Field(ge=1)] = 3
    node_recovery_success_threshold: Annotated[int, Field(ge=1)] = 3
    node_recovery_requires_admin: bool = True
    canary_check_interval_seconds: Annotated[int, Field(ge=1, le=60)] = 60
    canary_probe_urls_json: list[AnyHttpUrl] = Field(
        default_factory=lambda: [
            AnyHttpUrl("https://probe-a.example.test/health"),
            AnyHttpUrl("https://probe-b.example.test/health"),
        ]
    )
    canary_min_successful_targets: Annotated[int, Field(ge=1)] = 1
    node_credential_snapshot_ttl_seconds: Annotated[int, Field(gt=0)] = 300

    tariffs_json: dict[str, TariffSettings]
    robokassa_hash_algorithm: Literal["SHA256"] = "SHA256"
    robokassa_is_test: bool = True
    payments_production_enabled: bool = False

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw.startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use postgresql+asyncpg")
        return value

    @field_validator("token_hash_keyring_json")
    @classmethod
    def validate_token_keyring(
        cls, value: dict[str, dict[str, SecretStr]]
    ) -> dict[str, dict[str, SecretStr]]:
        expected = {"device", "pairing_session", "telegram_start", "node", "canary"}
        if set(value) != expected:
            raise ValueError(f"token keyring domains must be exactly {sorted(expected)}")

        seen: set[bytes] = set()
        for domain, versions in value.items():
            if not versions:
                raise ValueError(f"token keyring domain {domain} has no keys")
            for key_id, secret in versions.items():
                decoded = _decode_32_byte_key(secret, f"{domain}.{key_id}")
                if decoded in seen:
                    raise ValueError("token domains and versions must not reuse key material")
                seen.add(decoded)
        return value

    @field_validator("proxy_credentials_keyring_json")
    @classmethod
    def validate_proxy_keyring(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        if not value:
            raise ValueError("proxy credentials keyring must not be empty")
        for key_id, secret in value.items():
            _decode_32_byte_key(secret, f"proxy.{key_id}")
        return value

    @model_validator(mode="after")
    def validate_cross_field_invariants(self) -> Self:
        for domain, active_key_id in self.token_hash_active_key_ids_json.items():
            if domain not in self.token_hash_keyring_json:
                raise ValueError(f"unknown token domain in active key ids: {domain}")
            if active_key_id not in self.token_hash_keyring_json[domain]:
                raise ValueError(f"active token key {domain}.{active_key_id} does not exist")
        if set(self.token_hash_active_key_ids_json) != set(self.token_hash_keyring_json):
            raise ValueError("every token domain must have exactly one active key id")
        if self.proxy_credentials_active_key_id not in self.proxy_credentials_keyring_json:
            raise ValueError("active proxy encryption key does not exist")
        if self.outbox_retry_max_seconds < self.outbox_retry_base_seconds:
            raise ValueError("outbox max retry must be greater than or equal to base retry")
        if self.canary_min_successful_targets > len(self.canary_probe_urls_json):
            raise ValueError("canary target quorum exceeds configured targets")
        if len({url.host for url in self.canary_probe_urls_json}) < 2:
            raise ValueError("canary probes must use at least two independent hosts")

        tariff = self.tariffs_json.get("vpn_30d")
        if tariff is None or len(self.tariffs_json) != 1:
            raise ValueError("MVP must define exactly the vpn_30d tariff")
        if (tariff.amount_minor, tariff.period_days, tariff.currency, tariff.enabled) != (
            29_900,
            30,
            "RUB",
            True,
        ):
            raise ValueError("vpn_30d must be enabled and cost 299 RUB for 30 days")

        if self.app_env is AppEnvironment.PRODUCTION:
            self._validate_production_profile()
        return self

    def _validate_production_profile(self) -> None:
        urls = [str(url).rstrip("/") for url in self.public_control_urls_json]
        if len(urls) < 2 or len(set(urls)) != len(urls):
            raise ValueError("production requires at least two distinct control URLs")
        if any(not url.startswith("https://") for url in urls):
            raise ValueError("production control URLs must use HTTPS")
        if any(
            url.host is None or url.host.endswith(".test") for url in self.public_control_urls_json
        ):
            raise ValueError("production control URLs must not use placeholder hosts")
        if str(self.app_public_base_url).rstrip("/") != urls[0]:
            raise ValueError("APP_PUBLIC_BASE_URL must be the first public control URL")
        if "local-only" in self.database_url.get_secret_value().lower():
            raise ValueError("production DATABASE_URL contains a development placeholder")
        for domain, versions in self.token_hash_keyring_json.items():
            for key_id, secret in versions.items():
                decoded = _decode_32_byte_key(secret, f"{domain}.{key_id}")
                if len(set(decoded)) == 1:
                    raise ValueError("production token keyring contains a development dummy key")
        for key_id, secret in self.proxy_credentials_keyring_json.items():
            decoded = _decode_32_byte_key(secret, f"proxy.{key_id}")
            if len(set(decoded)) == 1:
                raise ValueError("production proxy keyring contains a development dummy key")
        if self.trial_duration_seconds != 86_400:
            raise ValueError("production trial must be 24 hours")
        if self.device_limit_per_user != 3:
            raise ValueError("production device limit must be 3")
        if not self.node_assignment_hard_capacity:
            raise ValueError("production node assignment must enforce hard capacity")
        if (self.node_block_failure_threshold, self.node_recovery_success_threshold) != (3, 3):
            raise ValueError("production canary thresholds must be 3 failures / 3 successes")
        if not self.node_recovery_requires_admin:
            raise ValueError("production node recovery must require administrator approval")
        if self.canary_check_interval_seconds != 60:
            raise ValueError("production canary interval must be 60 seconds")
        if self.telegram_delivery_mode != "webhook":
            raise ValueError("production Telegram delivery mode must be webhook")
        telegram_required = {
            "TELEGRAM_BOT_TOKEN": self.telegram_bot_token,
            "TELEGRAM_BOT_USERNAME": self.telegram_bot_username,
            "TELEGRAM_WEBHOOK_PUBLIC_BASE_URL": self.telegram_webhook_public_base_url,
            "TELEGRAM_WEBHOOK_SECRET": self.telegram_webhook_secret,
            "TELEGRAM_WEBHOOK_PATH_SECRET": self.telegram_webhook_path_secret,
        }
        missing = [name for name, value in telegram_required.items() if value is None]
        if missing:
            raise ValueError(f"missing production Telegram settings: {', '.join(missing)}")
        assert self.telegram_webhook_public_base_url is not None
        if not str(self.telegram_webhook_public_base_url).startswith("https://"):
            raise ValueError("production Telegram webhook URL must use HTTPS")
        for name, secret in (
            ("TELEGRAM_BOT_TOKEN", self.telegram_bot_token),
            ("TELEGRAM_WEBHOOK_SECRET", self.telegram_webhook_secret),
            ("TELEGRAM_WEBHOOK_PATH_SECRET", self.telegram_webhook_path_secret),
        ):
            assert secret is not None
            raw_secret = secret.get_secret_value()
            if len(raw_secret) < 32:
                raise ValueError(f"{name} must contain at least 32 characters")
            if "replace-with" in raw_secret.lower():
                raise ValueError(f"{name} contains a development placeholder")
        if self.payments_production_enabled:
            raise ValueError("production payments remain disabled until the fiscal gate is closed")
        if not self.robokassa_is_test:
            raise ValueError(
                "Robokassa must remain in test mode while production payments are disabled"
            )


def _decode_32_byte_key(secret: SecretStr, label: str) -> bytes:
    raw = secret.get_secret_value()
    try:
        decoded = base64.b64decode(
            raw + "=" * (-len(raw) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label} must be base64url") from exc
    if len(decoded) != 32:
        raise ValueError(f"{label} must decode to exactly 32 bytes")
    return decoded
