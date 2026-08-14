from __future__ import annotations

import base64
import ipaddress
import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


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
    device_limit: Annotated[int, Field(ge=1, le=10)]
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
    trial_bandwidth_limit_bytes_per_second: Annotated[int, Field(gt=0)] = 5_000_000
    pairing_token_ttl_seconds: Annotated[int, Field(gt=0)] = 600
    device_limit_per_user: Annotated[int, Field(gt=0)] = 3
    pairing_poll_after_seconds: Annotated[int, Field(ge=2, le=60)] = 2
    pairing_init_rate_per_minute: Annotated[int, Field(gt=0)] = 10
    pairing_init_rate_per_hour: Annotated[int, Field(gt=0)] = 30
    pairing_status_rate_per_minute: Annotated[int, Field(gt=0)] = 30
    status_rate_per_minute: Annotated[int, Field(gt=0)] = 120
    nodes_rate_per_minute: Annotated[int, Field(gt=0)] = 30
    node_select_rate_per_minute: Annotated[int, Field(gt=0)] = 10
    device_last_seen_write_interval_seconds: Annotated[int, Field(ge=60)] = 60
    rate_limit_retention_seconds: Annotated[int, Field(ge=3600)] = 7200
    rate_limit_cleanup_interval_seconds: Annotated[int, Field(ge=60)] = 3600
    trusted_proxy_cidrs: list[str] = Field(
        default_factory=lambda: ["127.0.0.1/32", "::1/128", "172.16.0.0/12"]
    )
    allowed_extension_origins_json: list[str] = Field(default_factory=list)
    discovery_signing_private_key: SecretStr | None = None
    discovery_signing_key_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,32}$")] = "v1"
    discovery_document_ttl_seconds: Annotated[int, Field(ge=300, le=86_400)] = 3600

    telegram_delivery_mode: Literal["webhook", "polling"] = "webhook"
    telegram_bot_token: SecretStr | None = None
    telegram_bot_username: str | None = None
    telegram_webhook_public_base_url: AnyHttpUrl | None = None
    telegram_webhook_secret: SecretStr | None = None
    telegram_webhook_path_secret: SecretStr | None = None
    telegram_update_max_body_bytes: Annotated[int, Field(ge=1, le=1_048_576)] = 1_048_576
    telegram_channel_url: AnyHttpUrl | None = None
    telegram_support_username: str | None = None
    chrome_web_store_url: AnyHttpUrl | None = None
    vpn_brand_name: Annotated[str, Field(min_length=1, max_length=32)] = "Virgo"
    subscription_reminder_poll_seconds: Annotated[int, Field(ge=60)] = 3600

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
    node_long_poll_max_wait_seconds: Annotated[int, Field(ge=1, le=30)] = 25
    node_long_poll_check_interval_seconds: Annotated[float, Field(gt=0, le=5)] = 0.5
    node_snapshot_ack_timeout_seconds: Annotated[int, Field(ge=1)] = 15
    node_snapshot_max_missed_acks: Annotated[int, Field(ge=1, le=10)] = 3
    node_snapshot_watch_interval_seconds: Annotated[float, Field(gt=0)] = 5
    node_snapshot_heartbeat_timeout_seconds: Annotated[int, Field(ge=30)] = 75
    internal_api_rate_per_minute: Annotated[int, Field(gt=0)] = 120
    node_snapshot_issue_retention_seconds: Annotated[int, Field(ge=3600)] = 86_400
    telemetry_install_rate_per_minute: Annotated[int, Field(gt=0)] = 30
    telemetry_device_rate_per_minute: Annotated[int, Field(gt=0)] = 120
    operations_health_poll_seconds: Annotated[int, Field(ge=30)] = 60
    operations_node_telemetry_stale_seconds: Annotated[int, Field(ge=60)] = 120
    operations_alert_cooldown_seconds: Annotated[int, Field(ge=300)] = 3600
    operations_cpu_warning_percent: Annotated[float, Field(ge=50, le=100)] = 90
    operations_memory_warning_percent: Annotated[float, Field(ge=50, le=100)] = 90
    operations_disk_warning_percent: Annotated[float, Field(ge=50, le=100)] = 85
    operations_tls_warning_days: Annotated[int, Field(ge=1, le=90)] = 14
    analytics_raw_event_retention_days: Annotated[int, Field(ge=7, le=365)] = 90
    analytics_cleanup_interval_seconds: Annotated[int, Field(ge=300)] = 3600

    admin_panel_enabled: bool = False
    admin_panel_username: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")] = "admin"
    admin_panel_password_hash: SecretStr | None = None
    admin_telegram_bot_token: SecretStr | None = None
    admin_telegram_chat_ids_json: list[int] = Field(default_factory=list)
    metrics_scrape_token: SecretStr | None = None

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
        if self.rate_limit_retention_seconds <= self.rate_limit_cleanup_interval_seconds:
            raise ValueError("rate limit retention must exceed its cleanup interval")
        for value in self.trusted_proxy_cidrs:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid trusted proxy CIDR: {value}") from exc
        if len(set(self.allowed_extension_origins_json)) != len(
            self.allowed_extension_origins_json
        ):
            raise ValueError("extension origins must be unique")
        extension_origin = re.compile(r"^chrome-extension://(?:[a-p]{32}|\*)$")
        if any(
            not extension_origin.fullmatch(origin) for origin in self.allowed_extension_origins_json
        ):
            raise ValueError(
                "extension origins must be exact Chrome extension origins or the temporary "
                "chrome-extension://* test pattern"
            )
        if self.telegram_bot_username is not None and not re.fullmatch(
            r"[A-Za-z0-9_]{5,32}", self.telegram_bot_username
        ):
            raise ValueError("TELEGRAM_BOT_USERNAME has an invalid format")
        if self.telegram_support_username is not None and not re.fullmatch(
            r"[A-Za-z0-9_]{5,32}", self.telegram_support_username
        ):
            raise ValueError("TELEGRAM_SUPPORT_USERNAME has an invalid format")
        if self.canary_min_successful_targets > len(self.canary_probe_urls_json):
            raise ValueError("canary target quorum exceeds configured targets")
        if len({url.host for url in self.canary_probe_urls_json}) < 2:
            raise ValueError("canary probes must use at least two independent hosts")
        if len(set(self.admin_telegram_chat_ids_json)) != len(self.admin_telegram_chat_ids_json):
            raise ValueError("admin Telegram chat IDs must be unique")
        if any(chat_id == 0 for chat_id in self.admin_telegram_chat_ids_json):
            raise ValueError("admin Telegram chat IDs must be non-zero")
        if (
            self.admin_panel_password_hash is not None
            and re.fullmatch(
                r"pbkdf2_sha256\$[1-9][0-9]{5,7}\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}",
                self.admin_panel_password_hash.get_secret_value(),
            )
            is None
        ):
            raise ValueError("ADMIN_PANEL_PASSWORD_HASH has an invalid format")
        if self.discovery_signing_private_key is not None:
            discovery_key = _decode_32_byte_key(
                self.discovery_signing_private_key,
                "DISCOVERY_SIGNING_PRIVATE_KEY",
            )
            discovery_scalar = int.from_bytes(discovery_key, "big")
            if not 1 <= discovery_scalar < _P256_ORDER:
                raise ValueError("DISCOVERY_SIGNING_PRIVATE_KEY is outside the P-256 range")

        expected_tariffs = {
            "vpn_15d": (14_900, 15, 2, "RUB", True),
            "vpn_30d": (29_900, 30, 5, "RUB", True),
        }
        if set(self.tariffs_json) != set(expected_tariffs):
            raise ValueError("tariffs must define exactly vpn_15d and vpn_30d")
        for code, expected in expected_tariffs.items():
            tariff = self.tariffs_json[code]
            actual = (
                tariff.amount_minor,
                tariff.period_days,
                tariff.device_limit,
                tariff.currency,
                tariff.enabled,
            )
            if actual != expected:
                raise ValueError(f"{code} does not match the approved Virgo tariff")

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
        if len({url.host for url in self.public_control_urls_json}) != 2:
            raise ValueError("production control URLs must use two distinct hostnames")
        if any(
            url.path not in {"", "/"}
            or url.query is not None
            or url.fragment is not None
            or url.username is not None
            or url.port not in {None, 443}
            for url in self.public_control_urls_json
        ):
            raise ValueError("production control URLs must be HTTPS origins on port 443")
        if str(self.app_public_base_url).rstrip("/") != urls[0]:
            raise ValueError("APP_PUBLIC_BASE_URL must be the first public control URL")
        trusted_networks = [
            ipaddress.ip_network(value, strict=False) for value in self.trusted_proxy_cidrs
        ]
        if len(trusted_networks) != 2 or len(set(trusted_networks)) != 2:
            raise ValueError("production must trust exactly two API proxy peer addresses")
        if any(network.prefixlen != network.max_prefixlen for network in trusted_networks):
            raise ValueError("production trusted proxies must use exact host CIDRs")
        if any(
            not network.network_address.is_private
            or network.network_address.is_loopback
            or network.network_address.is_link_local
            or network.network_address.is_unspecified
            or network.network_address.is_multicast
            or network.network_address.is_reserved
            for network in trusted_networks
        ):
            raise ValueError("production trusted proxies must be private WireGuard peer addresses")
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
        if self.trial_bandwidth_limit_bytes_per_second != 5_000_000:
            raise ValueError("production trial bandwidth limit must be 40 Mbit/s")
        if self.device_limit_per_user != 3:
            raise ValueError("production device limit must be 3")
        if (
            self.pairing_poll_after_seconds,
            self.pairing_init_rate_per_minute,
            self.pairing_init_rate_per_hour,
            self.pairing_status_rate_per_minute,
        ) != (2, 10, 30, 30):
            raise ValueError(
                "production pairing polling and rate limits must match the MVP profile"
            )
        if (
            self.status_rate_per_minute,
            self.nodes_rate_per_minute,
            self.node_select_rate_per_minute,
            self.device_last_seen_write_interval_seconds,
        ) != (120, 30, 10, 60):
            raise ValueError("production access endpoint limits must match the MVP profile")
        if not self.node_assignment_hard_capacity:
            raise ValueError("production node assignment must enforce hard capacity")
        if (self.node_block_failure_threshold, self.node_recovery_success_threshold) != (3, 3):
            raise ValueError("production canary thresholds must be 3 failures / 3 successes")
        if not self.node_recovery_requires_admin:
            raise ValueError("production node recovery must require administrator approval")
        if self.canary_check_interval_seconds != 60:
            raise ValueError("production canary interval must be 60 seconds")
        if (
            self.node_credential_snapshot_ttl_seconds,
            self.node_long_poll_max_wait_seconds,
            self.node_long_poll_check_interval_seconds,
            self.node_snapshot_ack_timeout_seconds,
            self.node_snapshot_max_missed_acks,
            self.node_snapshot_watch_interval_seconds,
            self.node_snapshot_heartbeat_timeout_seconds,
            self.internal_api_rate_per_minute,
        ) != (300, 25, 0.5, 15, 3, 5, 75, 120):
            raise ValueError("production node snapshot settings must match the MVP profile")
        if self.telegram_delivery_mode != "webhook":
            raise ValueError("production Telegram delivery mode must be webhook")
        if not self.admin_panel_enabled or self.admin_panel_password_hash is None:
            raise ValueError("production requires the password-protected admin panel")
        if self.admin_telegram_bot_token is None or not self.admin_telegram_chat_ids_json:
            raise ValueError("production requires the separate admin Telegram bot")
        if len(self.admin_telegram_bot_token.get_secret_value()) < 32:
            raise ValueError("ADMIN_TELEGRAM_BOT_TOKEN must contain at least 32 characters")
        if (
            self.metrics_scrape_token is None
            or len(self.metrics_scrape_token.get_secret_value()) < 32
        ):
            raise ValueError("production requires a strong metrics scrape token")
        if not self.allowed_extension_origins_json:
            raise ValueError("production requires at least one allowed extension origin")
        if self.discovery_signing_private_key is None:
            raise ValueError("production requires DISCOVERY_SIGNING_PRIVATE_KEY")
        discovery_key = _decode_32_byte_key(
            self.discovery_signing_private_key,
            "DISCOVERY_SIGNING_PRIVATE_KEY",
        )
        if int.from_bytes(discovery_key, "big") in {0, 1}:
            raise ValueError("production discovery signing key is a development dummy key")
        telegram_required = {
            "TELEGRAM_BOT_TOKEN": self.telegram_bot_token,
            "TELEGRAM_BOT_USERNAME": self.telegram_bot_username,
            "TELEGRAM_WEBHOOK_PUBLIC_BASE_URL": self.telegram_webhook_public_base_url,
            "TELEGRAM_WEBHOOK_SECRET": self.telegram_webhook_secret,
            "TELEGRAM_WEBHOOK_PATH_SECRET": self.telegram_webhook_path_secret,
            "TELEGRAM_CHANNEL_URL": self.telegram_channel_url,
            "TELEGRAM_SUPPORT_USERNAME": self.telegram_support_username,
            "CHROME_WEB_STORE_URL": self.chrome_web_store_url,
        }
        missing = [name for name, value in telegram_required.items() if value is None]
        if missing:
            raise ValueError(f"missing production Telegram settings: {', '.join(missing)}")
        assert self.telegram_webhook_public_base_url is not None
        if not str(self.telegram_webhook_public_base_url).startswith("https://"):
            raise ValueError("production Telegram webhook URL must use HTTPS")
        for name, url in (
            ("TELEGRAM_CHANNEL_URL", self.telegram_channel_url),
            ("CHROME_WEB_STORE_URL", self.chrome_web_store_url),
        ):
            assert url is not None
            if not str(url).startswith("https://"):
                raise ValueError(f"{name} must use HTTPS in production")
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
