from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vpn_service.application.health import DatabaseProbe
from vpn_service.config import Settings
from vpn_service.http.health import router as health_router
from vpn_service.http.middleware import RequestLoggingMiddleware
from vpn_service.logging import configure_logging
from vpn_service.persistence.database import Database


def create_app(
    settings: Settings | None = None,
    *,
    database_probe: DatabaseProbe | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings()  # type: ignore[call-arg]
    configure_logging(resolved_settings.log_level, resolved_settings.log_format)
    database = None if database_probe is not None else Database(resolved_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if database is not None:
            await database.dispose()

    app = FastAPI(
        title="VPN Control API",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.database = database
    app.state.database_probe = database_probe or database.probe  # type: ignore[union-attr]
    app.add_middleware(RequestLoggingMiddleware)
    app.include_router(health_router)
    return app
