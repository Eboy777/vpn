from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import Response

from vpn_service.application.metrics import MetricsService

router = APIRouter(tags=["metrics"])


@router.get("/internal/metrics")
async def metrics(request: Request) -> Response:
    configured = request.app.state.settings.metrics_scrape_token
    received = request.headers.get("authorization", "")
    expected = "Bearer " + (configured.get_secret_value() if configured is not None else "")
    if configured is None or not hmac.compare_digest(received, expected):
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    service: MetricsService | None = request.app.state.metrics_service
    if service is None:
        raise HTTPException(status_code=503)
    return Response(
        await service.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )
