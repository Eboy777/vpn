from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from vpn_service.canary_agent.config import (
    CanaryAgentSettings,
    CanaryNodeTarget,
    normalize_control_urls,
)

logger = logging.getLogger(__name__)


class CanaryAgent:
    def __init__(
        self,
        settings: CanaryAgentSettings,
        *,
        control_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._control_client = control_client or httpx.AsyncClient(
            timeout=settings.canary_request_timeout_seconds,
            follow_redirects=False,
        )
        self._owns_client = control_client is None
        self._pending_report: dict[str, object] | None = None
        self._control_urls = list(settings.control_urls)

    async def close(self) -> None:
        if self._owns_client:
            await self._control_client.aclose()

    async def check_once(self) -> dict[str, object]:
        if self._pending_report is None:
            checked_at = datetime.now(UTC)
            results = await asyncio.gather(
                *(self._check_node(node) for node in self._settings.canary_nodes_json)
            )
            ingress_results = await asyncio.gather(
                *(self._check_ingress(url) for url in self._control_urls)
            )
            self._pending_report = {
                "run_id": str(uuid.uuid4()),
                "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
                "nodes": results,
                "ingresses": ingress_results,
            }
        response = await self._report(self._pending_report)
        discovered = response.get("control_urls")
        if isinstance(discovered, list) and 2 <= len(discovered) <= 20:
            try:
                self._control_urls = normalize_control_urls([str(value) for value in discovered])
            except ValueError:
                logger.error("canary_discovery_urls_invalid")
        self._pending_report = None
        return response

    async def run_forever(self, stop: asyncio.Event) -> None:
        consecutive_failures = 0
        outage_alerted = False
        while not stop.is_set():
            try:
                await self.check_once()
                if outage_alerted:
                    await self._notify_admin("✅ Control API снова доступен российской канарейке.")
                consecutive_failures = 0
                outage_alerted = False
            except Exception:
                consecutive_failures += 1
                logger.error("canary_check_failed")
                if (
                    consecutive_failures >= self._settings.canary_control_failure_alert_after
                    and not outage_alerted
                ):
                    outage_alerted = await self._notify_admin(
                        "🚨 Control API недоступен российской канарейке "
                        f"{consecutive_failures} проверки подряд."
                    )
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._settings.canary_check_interval_seconds,
                )
            except TimeoutError:
                pass

    async def _check_node(self, node: CanaryNodeTarget) -> dict[str, object]:
        proxy_url = (
            "https://"
            + quote(node.username, safe="")
            + ":"
            + quote(node.password.get_secret_value(), safe="")
            + "@"
            + node.host
            + f":{node.port}"
        )
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=self._settings.canary_request_timeout_seconds,
            follow_redirects=False,
        ) as client:
            targets = await asyncio.gather(
                *(
                    self._check_target(client, str(url))
                    for url in self._settings.canary_probe_urls_json
                )
            )
        return {
            "check_id": str(uuid.uuid4()),
            "node_id": str(node.node_id),
            "targets": targets,
        }

    async def _check_ingress(self, base_url: str) -> dict[str, object]:
        started = time.perf_counter()
        try:
            response = await self._control_client.get(
                base_url + "/health/ready",
                headers={"Cache-Control": "no-cache"},
            )
            latency_ms = round((time.perf_counter() - started) * 1000, 3)
            if response.status_code == 200:
                return {
                    "url": base_url,
                    "success": True,
                    "latency_ms": latency_ms,
                    "status_code": response.status_code,
                    "error_code": None,
                }
            return {
                "url": base_url,
                "success": False,
                "latency_ms": latency_ms,
                "status_code": response.status_code,
                "error_code": "HTTP_STATUS",
            }
        except httpx.TimeoutException:
            error_code = "TIMEOUT"
        except httpx.ConnectError:
            error_code = "CONNECT_ERROR"
        except httpx.HTTPError:
            error_code = "NETWORK_ERROR"
        return {
            "url": base_url,
            "success": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "status_code": None,
            "error_code": error_code,
        }

    async def _check_target(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> dict[str, object]:
        started = time.perf_counter()
        target = httpx.URL(url).host
        try:
            async with client.stream("GET", url, headers={"Cache-Control": "no-cache"}) as response:
                status_code = response.status_code
            latency_ms = round((time.perf_counter() - started) * 1000, 3)
            if 200 <= status_code < 400:
                return {
                    "target": target,
                    "success": True,
                    "latency_ms": latency_ms,
                    "status_code": status_code,
                    "error_code": None,
                }
            return {
                "target": target,
                "success": False,
                "latency_ms": latency_ms,
                "status_code": status_code,
                "error_code": "HTTP_STATUS",
            }
        except httpx.TimeoutException:
            error_code = "TIMEOUT"
        except httpx.ProxyError:
            error_code = "PROXY_ERROR"
        except httpx.ConnectError:
            error_code = "CONNECT_ERROR"
        except httpx.HTTPError:
            error_code = "NETWORK_ERROR"
        return {
            "target": target,
            "success": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "status_code": None,
            "error_code": error_code,
        }

    async def _report(self, payload: dict[str, object]) -> dict[str, object]:
        path = f"/internal/canaries/{self._settings.canary_id}/checks"
        headers = {
            "Authorization": "Bearer " + self._settings.canary_token.get_secret_value(),
            "Content-Type": "application/json",
        }
        last_error: Exception | None = None
        for base_url in self._control_urls:
            try:
                response = await self._control_client.post(
                    base_url + path,
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, dict):
                    raise RuntimeError("canary report response is invalid")
                return body
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                last_error = exc
        raise last_error or RuntimeError("all control API URLs failed")

    async def _notify_admin(self, text: str) -> bool:
        token = self._settings.canary_admin_telegram_bot_token
        if token is None:
            return False
        endpoint = "https://api.telegram.org/bot" + token.get_secret_value() + "/sendMessage"
        try:
            for chat_id in self._settings.canary_admin_telegram_chat_ids_json:
                response = await self._control_client.post(
                    endpoint,
                    json={
                        "chat_id": chat_id,
                        "text": text,
                        "disable_web_page_preview": True,
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError:
            logger.error("canary_admin_alert_failed")
            return False
        return True
