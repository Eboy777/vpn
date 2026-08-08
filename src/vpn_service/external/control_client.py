from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

_FAILOVER_STATUSES = frozenset({408, 502, 503, 504})
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ControlPlaneUnavailable(RuntimeError):
    """All configured control ingress URLs failed with a retryable error."""


@dataclass(frozen=True, slots=True)
class ControlClientPolicy:
    attempts_per_url: int = 2
    backoff_base_seconds: float = 0.25
    backoff_max_seconds: float = 2.0

    def __post_init__(self) -> None:
        if self.attempts_per_url < 1:
            raise ValueError("attempts_per_url must be positive")
        if self.backoff_base_seconds < 0:
            raise ValueError("backoff_base_seconds must not be negative")
        if self.backoff_max_seconds < self.backoff_base_seconds:
            raise ValueError("backoff max must be greater than or equal to base")


class ControlPlaneClient:
    """Reference implementation of the primary/fallback policy used by control clients."""

    def __init__(
        self,
        base_urls: Sequence[str],
        *,
        client: httpx.AsyncClient,
        policy: ControlClientPolicy | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._base_urls = validate_control_urls(base_urls)
        self._client = client
        self._policy = policy or ControlClientPolicy()
        self._sleep = sleep
        self._clock = clock
        self._rate_limited_until = 0.0

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        normalized_method = method.upper()
        if normalized_method not in _IDEMPOTENT_METHODS:
            raise ValueError("automatic failover is limited to idempotent HTTP methods")
        if not path.startswith("/") or urlsplit(path).netloc:
            raise ValueError("path must be an origin-relative absolute path")

        rate_limit_delay = self._rate_limited_until - self._clock()
        if rate_limit_delay > 0:
            await self._sleep(rate_limit_delay)

        request_headers = httpx.Headers(headers)
        if "X-Request-ID" not in request_headers:
            request_headers["X-Request-ID"] = str(uuid.uuid4())

        failures: list[str] = []
        for attempt in range(self._policy.attempts_per_url):
            for base_url in self._base_urls:
                url = f"{base_url}{path}"
                try:
                    response = await self._client.request(
                        normalized_method,
                        url,
                        headers=request_headers,
                    )
                except httpx.TransportError as exc:
                    failures.append(f"{base_url}:transport:{type(exc).__name__}")
                    continue

                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "")
                    if retry_after.isdecimal():
                        self._rate_limited_until = max(
                            self._rate_limited_until,
                            self._clock() + int(retry_after),
                        )
                    return response
                if response.status_code not in _FAILOVER_STATUSES:
                    return response
                failures.append(f"{base_url}:http:{response.status_code}")
                await response.aclose()

            if attempt + 1 < self._policy.attempts_per_url:
                delay = min(
                    self._policy.backoff_base_seconds * (2**attempt),
                    self._policy.backoff_max_seconds,
                )
                await self._sleep(delay)

        summary = ", ".join(failures)
        raise ControlPlaneUnavailable(f"all control ingress attempts failed ({summary})")


def validate_control_urls(base_urls: Sequence[str]) -> tuple[str, str]:
    normalized = tuple(value.rstrip("/") for value in base_urls)
    if len(normalized) != 2 or len(set(normalized)) != 2:
        raise ValueError("exactly two distinct control URLs are required")
    for value in normalized:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.port not in {None, 443}:
            raise ValueError("control URLs must be absolute HTTPS URLs")
        if (
            parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("control URLs must not contain path, credentials, query, or fragment")
    if len({urlsplit(value).hostname for value in normalized}) != 2:
        raise ValueError("control URLs must use two distinct hostnames")
    return normalized[0], normalized[1]
