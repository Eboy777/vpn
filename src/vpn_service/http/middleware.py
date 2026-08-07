from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from vpn_service.logging import sanitize_path

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = _request_id(request.headers.get("x-request-id"))
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "unhandled_request_error",
                extra={
                    "event_data": {
                        "event": "http_request",
                        "request_id": request_id,
                        "method": request.method,
                        "path": sanitize_path(request.url.path),
                        "status_code": 500,
                    }
                },
            )
            raise
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request_completed",
            extra={
                "event_data": {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": sanitize_path(request.url.path),
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                }
            },
        )
        return response


def _request_id(raw_value: str | None) -> str:
    if raw_value is not None:
        try:
            return str(uuid.UUID(raw_value))
        except ValueError:
            pass
    return str(uuid.uuid4())
