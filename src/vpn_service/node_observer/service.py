from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
from cryptography import x509
from fastapi import FastAPI, Request
from pydantic import BaseModel, ConfigDict, Field

from vpn_service.node_observer.config import NodeObserverSettings

_MAX_I64 = 2**63 - 1


class ObserverStats(BaseModel):
    model_config = ConfigDict(extra="ignore")

    totalConns: Annotated[int, Field(ge=0, le=_MAX_I64)] = 0
    currentConns: Annotated[int, Field(ge=0, le=_MAX_I64)] = 0
    inputBytes: Annotated[int, Field(ge=0, le=_MAX_I64)] = 0
    outputBytes: Annotated[int, Field(ge=0, le=_MAX_I64)] = 0
    totalErrs: Annotated[int, Field(ge=0, le=_MAX_I64)] = 0


class ObserverEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str
    type: str
    client: Annotated[str, Field(max_length=128)] | None = None
    stats: ObserverStats | None = None


class ObserverPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: Annotated[list[ObserverEvent], Field(max_length=10_000)]


class LimiterRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    scope: str
    client: Annotated[str, Field(max_length=128)] | None = None


@dataclass(slots=True)
class TrafficDelta:
    total_connections: int = 0
    current_connections: int = 0
    input_bytes: int = 0
    output_bytes: int = 0
    total_errors: int = 0
    connection_seconds: int = 0

    def add(self, stats: ObserverStats, period_seconds: int) -> None:
        self.total_connections = _saturated_add(self.total_connections, stats.totalConns)
        self.current_connections = stats.currentConns
        self.input_bytes = _saturated_add(self.input_bytes, stats.inputBytes)
        self.output_bytes = _saturated_add(self.output_bytes, stats.outputBytes)
        self.total_errors = _saturated_add(self.total_errors, stats.totalErrs)
        self.connection_seconds = _saturated_add(
            self.connection_seconds, stats.currentConns * period_seconds
        )


class NodeObserver:
    def __init__(
        self,
        settings: NodeObserverSettings,
        *,
        client: httpx.AsyncClient | None = None,
        service_probe: Callable[[str], Awaitable[bool]] | None = None,
    ) -> None:
        self._settings = settings
        self._client = client or httpx.AsyncClient(
            timeout=settings.node_observer_http_timeout_seconds,
            follow_redirects=False,
        )
        self._owns_client = client is None
        self._service_probe = service_probe or _service_is_active
        self._lock = asyncio.Lock()
        self._flush_lock = asyncio.Lock()
        self._pending: dict[str, TrafficDelta] = {}
        self._inflight: dict[str, object] | None = None
        self._previous_cpu: tuple[int, int] | None = None
        self._limits_mtime_ns: int | None = None
        self._account_limits: dict[str, int] = {}

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def observe(self, payload: ObserverPayload) -> int:
        accepted = 0
        async with self._lock:
            for event in payload.events:
                if (
                    event.kind != "handler"
                    or event.type != "stats"
                    or event.client is None
                    or event.stats is None
                    or not event.client.startswith("u_")
                ):
                    continue
                delta = self._pending.setdefault(event.client, TrafficDelta())
                delta.add(event.stats, self._settings.node_observer_report_interval_seconds)
                accepted += 1
        return accepted

    def account_limit(self, request: LimiterRequest) -> dict[str, int]:
        if request.scope != "client" or request.client is None:
            return {"in": 0, "out": 0}
        self._reload_account_limits()
        value = self._account_limits.get(request.client, 0)
        return {"in": value, "out": value}

    def _reload_account_limits(self) -> None:
        path = self._settings.gost_account_limits_path
        try:
            stat = path.stat()
            if stat.st_mtime_ns == self._limits_mtime_ns:
                return
            raw = json.loads(path.read_text())
            if not isinstance(raw, dict):
                raise ValueError("account limits must be an object")
            parsed = {
                username: value
                for username, value in raw.items()
                if isinstance(username, str)
                and username.startswith("u_")
                and isinstance(value, int)
                and not isinstance(value, bool)
                and 0 <= value <= 10**10
            }
            if len(parsed) != len(raw):
                raise ValueError("account limits contain an invalid entry")
        except (OSError, ValueError, TypeError):
            return
        self._account_limits = parsed
        self._limits_mtime_ns = stat.st_mtime_ns

    async def flush(self) -> bool:
        async with self._flush_lock:
            async with self._lock:
                payload = self._inflight
                if payload is None:
                    pending, self._pending = self._pending, {}
            if payload is None:
                payload = {
                    "report_id": str(uuid.uuid4()),
                    "observed_at": _utc_now(),
                    "clients": [
                        {
                            "proxy_username": username,
                            "total_connections": item.total_connections,
                            "current_connections": item.current_connections,
                            "input_bytes": item.input_bytes,
                            "output_bytes": item.output_bytes,
                            "total_errors": item.total_errors,
                            "connection_seconds": item.connection_seconds,
                        }
                        for username, item in sorted(pending.items())
                    ],
                    "runtime": await self._runtime_metrics(),
                }
                async with self._lock:
                    self._inflight = payload
            path = f"/internal/nodes/{self._settings.node_id}/telemetry"
            headers = {
                "Authorization": (
                    "Bearer " + self._settings.node_credentials_token.get_secret_value()
                ),
                "Content-Type": "application/json",
            }
            try:
                await self._post_with_fallback(path, headers=headers, payload=payload)
            except (httpx.HTTPError, ValueError, RuntimeError):
                return False
            async with self._lock:
                if self._inflight is payload:
                    self._inflight = None
            return True

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.flush()
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._settings.node_observer_report_interval_seconds,
                )
            except TimeoutError:
                pass

    async def _post_with_fallback(
        self,
        path: str,
        *,
        headers: dict[str, str],
        payload: dict[str, object],
    ) -> None:
        last_error: Exception | None = None
        for base_url in self._settings.control_urls:
            try:
                response = await self._client.post(base_url + path, headers=headers, json=payload)
                response.raise_for_status()
                return
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
        raise last_error or RuntimeError("all control API URLs failed")

    async def _runtime_metrics(self) -> dict[str, object]:
        cpu = _read_cpu_percent(self._previous_cpu)
        self._previous_cpu = cpu.sample
        memory_percent = _read_memory_percent()
        disk = shutil.disk_usage(self._settings.node_metrics_disk_path)
        rx_bytes, tx_bytes = _read_network_bytes()
        return {
            "cpu_percent": cpu.percent,
            "memory_percent": memory_percent,
            "disk_percent": round((disk.used / disk.total) * 100, 3) if disk.total else 0.0,
            "network_rx_bytes": rx_bytes,
            "network_tx_bytes": tx_bytes,
            "gost_up": await self._service_probe("gost"),
            "sync_agent_up": await self._service_probe("vpn-node-sync"),
            "tls_expires_at": _certificate_expiry(self._settings.node_tls_cert_path),
        }


@dataclass(frozen=True, slots=True)
class CpuSample:
    percent: float
    sample: tuple[int, int]


def _saturated_add(first: int, second: int) -> int:
    return min(_MAX_I64, first + second)


def create_observer_app(
    settings: NodeObserverSettings,
    observer: NodeObserver | None = None,
) -> FastAPI:
    resolved = observer or NodeObserver(settings)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.observer = resolved

    @app.post("/observer")
    async def observe(request: Request, payload: ObserverPayload) -> dict[str, bool]:
        if request.client is None or request.client.host not in {"127.0.0.1", "::1"}:
            return {"ok": False}
        await resolved.observe(payload)
        return {"ok": True}

    @app.post("/limiter")
    async def limit(request: Request, payload: LimiterRequest) -> dict[str, int]:
        if request.client is None or request.client.host not in {"127.0.0.1", "::1"}:
            return {"in": 0, "out": 0}
        return resolved.account_limit(payload)

    return app


def _read_cpu_percent(previous: tuple[int, int] | None) -> CpuSample:
    try:
        fields = [
            int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        ]
    except (OSError, ValueError, IndexError):
        return CpuSample(0.0, previous or (0, 0))
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    total = sum(fields)
    if previous is None or total <= previous[0]:
        return CpuSample(0.0, (total, idle))
    total_delta = total - previous[0]
    idle_delta = idle - previous[1]
    return CpuSample(round((1 - idle_delta / total_delta) * 100, 3), (total, idle))


def _read_memory_percent() -> float:
    try:
        values = {
            line.split(":", 1)[0]: int(line.split()[1])
            for line in Path("/proc/meminfo").read_text().splitlines()
            if ":" in line
        }
        total = values["MemTotal"]
        available = values["MemAvailable"]
    except (OSError, ValueError, KeyError, IndexError):
        return 0.0
    return round((1 - available / total) * 100, 3) if total else 0.0


def _read_network_bytes() -> tuple[int, int]:
    rx = 0
    tx = 0
    try:
        lines = Path("/proc/net/dev").read_text().splitlines()[2:]
        for line in lines:
            name, raw = line.split(":", 1)
            if name.strip() == "lo":
                continue
            fields = raw.split()
            rx += int(fields[0])
            tx += int(fields[8])
    except (OSError, ValueError, IndexError):
        return 0, 0
    return rx, tx


def _certificate_expiry(path: Path) -> str | None:
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return None
    return certificate.not_valid_after_utc.astimezone(UTC).isoformat().replace("+00:00", "Z")


async def _service_is_active(service: str) -> bool:
    try:
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "is-active",
            "--quiet",
            service,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await asyncio.wait_for(process.wait(), timeout=3) == 0
    except (OSError, TimeoutError):
        return False


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
