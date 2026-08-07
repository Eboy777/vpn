from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from vpn_service.config import LogFormat

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"authorization|cookie|token|secret|password|credential|signature|receipt|database_url",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_PAIRING_QUERY = re.compile(r"(?i)([?&]start=)[^&#\s]+")
_WEBHOOK_PATH = re.compile(r"(/integrations/telegram/webhook/)[^/?#\s]+")


def redact(value: Any, *, key: str | None = None) -> Any:
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(item_key): redact(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = _BEARER.sub(f"Bearer {REDACTED}", value)
        value = _PAIRING_QUERY.sub(rf"\1{REDACTED}", value)
        value = _WEBHOOK_PATH.sub(rf"\1{REDACTED}", value)
    return value


def sanitize_path(path: str) -> str:
    return str(redact(path))


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.msg)
        if isinstance(record.args, Mapping):
            record.args = redact(record.args)
        elif isinstance(record.args, tuple):
            record.args = tuple(redact(item) for item in record.args)
        if hasattr(record, "event_data"):
            record.event_data = redact(record.event_data)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event_data = getattr(record, "event_data", None)
        if isinstance(event_data, Mapping):
            payload.update(redact(event_data))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(redact(payload), ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str, log_format: LogFormat) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    if log_format is LogFormat.JSON:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
