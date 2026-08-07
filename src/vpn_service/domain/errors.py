from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    field: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ApplicationError(Exception):
    status_code: int
    code: str
    message: str
    details: tuple[ErrorDetail, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)
