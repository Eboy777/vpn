from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vpn_service.application.access import AccessService
from vpn_service.application.admin_dashboard import AdminDashboardService
from vpn_service.application.canary import CanaryAuthenticator, CanaryReportService
from vpn_service.application.device_auth import DeviceAuthenticator
from vpn_service.application.health import DatabaseProbe
from vpn_service.application.metrics import MetricsService
from vpn_service.application.node_credentials import NodeAuthenticator, NodeCredentialsService
from vpn_service.application.node_telemetry import NodeTelemetryService
from vpn_service.application.pairing import PairingService
from vpn_service.application.telegram_bot import TelegramBotService
from vpn_service.application.telemetry import TelemetryService
from vpn_service.config import Settings
from vpn_service.http.access import router as access_router
from vpn_service.http.admin import router as admin_router
from vpn_service.http.admin_headers import AdminSecurityHeadersMiddleware
from vpn_service.http.canary import router as canary_router
from vpn_service.http.contract import RequestContractMiddleware
from vpn_service.http.cors import ExtensionCorsMiddleware
from vpn_service.http.errors import install_error_handlers
from vpn_service.http.health import router as health_router
from vpn_service.http.metrics import router as metrics_router
from vpn_service.http.middleware import RequestLoggingMiddleware
from vpn_service.http.node_credentials import router as node_credentials_router
from vpn_service.http.pairing import router as pairing_router
from vpn_service.http.responses import ContractJSONResponse
from vpn_service.http.telegram import router as telegram_router
from vpn_service.http.telemetry import router as telemetry_router
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
        default_response_class=ContractJSONResponse,
    )
    app.state.settings = resolved_settings
    app.state.database = database
    app.state.database_probe = database_probe or database.probe  # type: ignore[union-attr]
    pairing_service = (
        PairingService(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.pairing_service = pairing_service
    app.state.telegram_bot_service = (
        TelegramBotService(database.sessions, resolved_settings, pairing_service)
        if database is not None and pairing_service is not None
        else None
    )
    app.state.device_authenticator = (
        DeviceAuthenticator(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.access_service = (
        AccessService(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.node_authenticator = (
        NodeAuthenticator(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.node_credentials_service = (
        NodeCredentialsService(database.sessions, resolved_settings)
        if database is not None
        else None
    )
    app.state.node_telemetry_service = (
        NodeTelemetryService(database.sessions) if database is not None else None
    )
    app.state.telemetry_service = (
        TelemetryService(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.canary_authenticator = (
        CanaryAuthenticator(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.canary_report_service = (
        CanaryReportService(database.sessions, resolved_settings) if database is not None else None
    )
    app.state.admin_dashboard_service = (
        AdminDashboardService(database.sessions) if database is not None else None
    )
    app.state.metrics_service = MetricsService(database.sessions) if database is not None else None
    install_error_handlers(app)
    app.add_middleware(RequestContractMiddleware)
    app.add_middleware(AdminSecurityHeadersMiddleware)
    app.add_middleware(
        ExtensionCorsMiddleware,
        allowed_origins=resolved_settings.allowed_extension_origins_json,
    )
    app.add_middleware(RequestLoggingMiddleware)
    app.include_router(health_router)
    app.include_router(pairing_router)
    app.include_router(telegram_router)
    app.include_router(access_router)
    app.include_router(node_credentials_router)
    app.include_router(telemetry_router)
    app.include_router(canary_router)
    app.include_router(admin_router)
    app.include_router(metrics_router)
    return app
