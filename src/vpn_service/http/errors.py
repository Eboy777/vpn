from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from vpn_service.domain.errors import ApplicationError
from vpn_service.http.responses import error_response


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApplicationError)
    async def application_error_handler(request: Request, exc: ApplicationError):
        return error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            request_id=request.state.request_id,
            details=[{"field": item.field, "reason": item.reason} for item in exc.details],
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        details = []
        for item in exc.errors()[:32]:
            location = ".".join(str(part) for part in item["loc"])
            reason = str(item["type"]).replace(".", "_")[:64]
            details.append({"field": location, "reason": reason})
        return error_response(
            status_code=400,
            code="INVALID_REQUEST",
            message="Request validation failed",
            request_id=request.state.request_id,
            details=details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 405:
            code, message = "METHOD_NOT_ALLOWED", "Method not allowed"
        else:
            code, message = "NOT_FOUND", "Resource not found"
        return error_response(
            status_code=exc.status_code,
            code=code,
            message=message,
            request_id=request.state.request_id,
            headers=exc.headers,
        )
