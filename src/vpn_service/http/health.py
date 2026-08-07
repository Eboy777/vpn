from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from vpn_service.application.health import check_database

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    database_ready = await check_database(request.app.state.database_probe)
    if database_ready:
        return JSONResponse({"status": "ok", "database": "ok"})
    return JSONResponse(
        {"status": "unavailable", "database": "unavailable"},
        status_code=503,
    )
