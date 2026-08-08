from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from collections.abc import Sequence

import httpx

from vpn_service.external.control_client import validate_control_urls


async def check_ingresses(
    urls: Sequence[str],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, object]]:
    normalized = validate_control_urls(urls)
    results: list[dict[str, object]] = []
    timeout = httpx.Timeout(connect=5, read=10, write=10, pool=5)
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        for base_url in normalized:
            response = await client.get(f"{base_url}/health/ready")
            request_id = response.headers.get("x-request-id")
            try:
                body = response.json()
            except ValueError as exc:
                raise RuntimeError(f"{base_url} returned non-JSON readiness") from exc
            if response.status_code != 200 or body != {"status": "ok", "database": "ok"}:
                raise RuntimeError(
                    f"{base_url} is not ready: status={response.status_code} body={body!r}"
                )
            if not request_id:
                raise RuntimeError(f"{base_url} did not return X-Request-ID")
            try:
                uuid.UUID(request_id)
            except ValueError as exc:
                raise RuntimeError(f"{base_url} returned an invalid X-Request-ID") from exc
            results.append(
                {
                    "url": base_url,
                    "status": "ready",
                    "request_id": request_id,
                }
            )
    return results


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify both public VPN control ingress readiness endpoints"
    )
    parser.add_argument("--url", action="append", required=True, help="public HTTPS control URL")
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        results = asyncio.run(check_ingresses(args.url))
    except (ValueError, RuntimeError, httpx.HTTPError) as exc:
        raise SystemExit(f"API proxy check failed: {exc}") from exc
    print(json.dumps({"ingresses": results}, separators=(",", ":")))
