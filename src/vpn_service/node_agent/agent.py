from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import httpx

from vpn_service.node_agent.config import NodeAgentSettings
from vpn_service.node_agent.models import (
    AckResponse,
    AgentState,
    CredentialsSnapshot,
    SnapshotCredential,
)
from vpn_service.node_agent.storage import AtomicFiles, render_auth_file

logger = logging.getLogger(__name__)
CommandRunner = Callable[[tuple[str, ...], float], Awaitable[None]]
RELOAD_COMMAND = ("systemctl", "reload-or-restart", "gost")
HEALTH_COMMAND = ("systemctl", "is-active", "--quiet", "gost")
RETRYABLE_STATUSES = {408, 502, 503, 504}


class RetryAfterError(RuntimeError):
    def __init__(self, seconds: int) -> None:
        super().__init__("control API rate limit")
        self.seconds = seconds


class NodeSyncAgent:
    def __init__(
        self,
        settings: NodeAgentSettings,
        *,
        client: httpx.AsyncClient | None = None,
        command_runner: CommandRunner | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._client = client or httpx.AsyncClient(
            timeout=settings.node_sync_timeout_seconds,
            follow_redirects=False,
        )
        self._owns_client = client is None
        self._run_command = command_runner or _run_command
        self._clock = clock or (lambda: datetime.now(UTC))
        self._files = AtomicFiles(
            settings.gost_config_path,
            settings.gost_config_staging_path,
            settings.node_sync_state_path,
            settings.gost_account_limits_path,
            settings.gost_account_limits_staging_path,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def run_forever(self, stop: asyncio.Event) -> None:
        self._files.verify_same_filesystem()
        await self._ensure_startup_state()
        while not stop.is_set():
            delay = 0.0
            try:
                await self.sync_once()
            except RetryAfterError as exc:
                delay = max(self._error_retry_delay(), exc.seconds)
                logger.warning("node_sync_rate_limited", extra={"retry_after": exc.seconds})
            except Exception:
                logger.exception("node_sync_failed")
                await self._fail_closed_if_expired()
                delay = self._error_retry_delay()
            if delay <= 0:
                await asyncio.sleep(0)
                continue
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                pass

    async def sync_once(self) -> None:
        state = self._files.load_state()
        if state.ack_pending and state.revision is not None:
            await self._acknowledge(state.revision)
            state = state.model_copy(update={"ack_pending": False})
            self._files.save_state(state)

        response = await self._request_snapshot(state)
        if response.status_code == 304:
            updated = self._state_from_304(response, state)
            self._files.save_state(updated)
            return

        snapshot = self._validate_snapshot_response(response)
        if snapshot.node_id != self._settings.node_id:
            raise RuntimeError("snapshot node identity mismatch")
        await self._apply_snapshot(
            self._render(snapshot.credentials),
            self._render_limits(snapshot.credentials),
        )
        pending = AgentState(
            revision=snapshot.revision,
            snapshot_valid_until=snapshot.snapshot_valid_until,
            ack_pending=True,
            failed_closed=False,
        )
        self._files.save_state(pending)
        await self._acknowledge(snapshot.revision)
        self._files.save_state(pending.model_copy(update={"ack_pending": False}))

    async def _ensure_startup_state(self) -> None:
        try:
            state = self._files.load_state()
        except Exception:
            logger.exception("node_sync_state_invalid")
            await self._apply_fail_closed()
            return
        if (
            state.failed_closed
            or state.snapshot_valid_until is None
            or not self._files.active_path.exists()
        ):
            await self._apply_fail_closed()
            return
        await self._fail_closed_if_expired()

    async def _fail_closed_if_expired(self) -> None:
        try:
            state = self._files.load_state()
        except Exception:
            await self._apply_fail_closed()
            return
        if state.snapshot_valid_until is None or (
            self._now() >= state.snapshot_valid_until.astimezone(UTC) and not state.failed_closed
        ):
            await self._apply_fail_closed()

    async def _apply_fail_closed(self) -> None:
        await self._apply_snapshot(self._render([]), self._render_limits([]))
        self._files.save_state(AgentState(failed_closed=True))
        logger.warning("node_credentials_failed_closed")

    async def _apply_snapshot(self, auth_content: bytes, limits_content: bytes) -> None:
        previous_auth = self._files.replace_auth(auth_content)
        try:
            previous_limits = self._files.replace_limits(limits_content)
        except BaseException:
            self._files.restore_auth(previous_auth)
            raise
        try:
            await self._run_command(
                RELOAD_COMMAND,
                self._settings.gost_reload_timeout_seconds,
            )
            await self._run_command(
                HEALTH_COMMAND,
                self._settings.gost_reload_timeout_seconds,
            )
        except BaseException:
            self._files.restore_auth(previous_auth)
            self._files.restore_limits(previous_limits)
            await self._run_command(
                RELOAD_COMMAND,
                self._settings.gost_reload_timeout_seconds,
            )
            raise

    async def _request_snapshot(self, state: AgentState) -> httpx.Response:
        headers = self._authorization_headers()
        if state.revision is not None and not state.failed_closed:
            headers["If-None-Match"] = f'"sha256:{state.revision}"'
        path = (
            f"/internal/nodes/{self._settings.node_id}/credentials"
            f"?wait_seconds={self._settings.node_long_poll_wait_seconds}"
        )
        return await self._request_with_fallback("GET", path, headers=headers)

    async def _acknowledge(self, revision: str) -> None:
        path = f"/internal/nodes/{self._settings.node_id}/credentials/ack"
        response = await self._request_with_fallback(
            "POST",
            path,
            headers={**self._authorization_headers(), "Content-Type": "application/json"},
            json_body={"revision": revision},
        )
        parsed = AckResponse.model_validate_json(response.content)
        if parsed.node_id != self._settings.node_id or parsed.revision != revision:
            raise RuntimeError("snapshot ack identity mismatch")

    async def _request_with_fallback(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        json_body: dict[str, str] | None = None,
    ) -> httpx.Response:
        last_error: Exception | None = None
        for index, base_url in enumerate(self._settings.control_urls):
            try:
                response = await self._client.request(
                    method,
                    base_url + path,
                    headers=headers,
                    json=json_body,
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                continue
            if response.status_code == 429:
                raise RetryAfterError(_retry_after(response))
            if response.status_code in RETRYABLE_STATUSES and index + 1 < len(
                self._settings.control_urls
            ):
                last_error = RuntimeError(f"retryable control status {response.status_code}")
                continue
            if response.status_code != 304:
                response.raise_for_status()
            if len(response.content) > 10_485_760:
                raise RuntimeError("control response exceeds maximum size")
            return response
        raise last_error or RuntimeError("all control API URLs failed")

    def _validate_snapshot_response(self, response: httpx.Response) -> CredentialsSnapshot:
        if response.status_code != 200:
            raise RuntimeError("snapshot response must be 200 or 304")
        snapshot = CredentialsSnapshot.model_validate_json(response.content)
        if _snapshot_revision(snapshot) != snapshot.revision:
            raise RuntimeError("snapshot revision checksum mismatch")
        expected_headers = {
            "etag": f'"sha256:{snapshot.revision}"',
            "x-snapshot-generated-at": _format_datetime(snapshot.generated_at),
            "x-snapshot-valid-until": _format_datetime(snapshot.snapshot_valid_until),
        }
        for name, expected in expected_headers.items():
            if response.headers.get(name) != expected:
                raise RuntimeError(f"snapshot {name} header mismatch")
        return snapshot

    def _state_from_304(self, response: httpx.Response, state: AgentState) -> AgentState:
        if state.revision is None or state.failed_closed:
            raise RuntimeError("304 cannot restore a missing local snapshot")
        if response.content or "content-type" in response.headers:
            raise RuntimeError("304 snapshot response must not have a body")
        etag = response.headers.get("etag")
        if etag != f'"sha256:{state.revision}"':
            raise RuntimeError("304 ETag does not match local revision")
        generated = _parse_datetime_header(response, "x-snapshot-generated-at")
        valid_until = _parse_datetime_header(response, "x-snapshot-valid-until")
        if valid_until <= generated:
            raise RuntimeError("304 snapshot lease is invalid")
        return state.model_copy(update={"snapshot_valid_until": valid_until})

    def _render(self, credentials: list[SnapshotCredential]) -> bytes:
        return render_auth_file(
            credentials,
            canary_username=self._settings.gost_canary_proxy_username,
            canary_password=self._settings.gost_canary_proxy_password.get_secret_value(),
            canary_version=self._settings.gost_canary_credential_version,
        )

    @staticmethod
    def _render_limits(credentials: list[SnapshotCredential]) -> bytes:
        payload = {
            item.proxy_username: item.bandwidth_limit_bytes_per_second
            for item in credentials
        }
        return (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode()

    def _authorization_headers(self) -> dict[str, str]:
        return {
            "Authorization": ("Bearer " + self._settings.node_credentials_token.get_secret_value())
        }

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise RuntimeError("node agent clock must be timezone-aware")
        return value.astimezone(UTC)

    def _error_retry_delay(self) -> float:
        return self._settings.node_sync_interval_seconds + random.uniform(
            0,
            self._settings.node_sync_jitter_seconds,
        )


async def _run_command(command: tuple[str, ...], timeout_seconds: float) -> None:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        return_code = await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError("GOST supervisor command timed out") from None
    if return_code != 0:
        raise RuntimeError("GOST supervisor command failed")


def _retry_after(response: httpx.Response) -> int:
    try:
        return max(1, min(3600, int(response.headers.get("retry-after", "60"))))
    except ValueError:
        return 60


def _parse_datetime_header(response: httpx.Response, name: str) -> datetime:
    raw = response.headers.get(name)
    if raw is None:
        raise RuntimeError(f"missing {name} header")
    value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise RuntimeError(f"invalid {name} timezone")
    return value.astimezone(UTC)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _snapshot_revision(snapshot: CredentialsSnapshot) -> str:
    canonical = {
        "node_status": snapshot.node_status,
        "credentials": [
            {
                "proxy_username": item.proxy_username,
                "proxy_password": item.proxy_password,
                "valid_until": _format_datetime(item.valid_until),
                "bandwidth_limit_bytes_per_second": item.bandwidth_limit_bytes_per_second,
            }
            for item in snapshot.credentials
        ],
    }
    payload = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()
