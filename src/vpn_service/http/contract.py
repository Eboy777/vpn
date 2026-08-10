from __future__ import annotations

import re

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from vpn_service.http.responses import error_response


class RequestContractMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        json_post = request.url.path in {
            "/api/pairing/init",
            "/api/nodes/select",
            "/api/telemetry/lifecycle",
            "/api/telemetry/events",
        } or bool(
            re.fullmatch(
                r"/internal/nodes/[0-9a-f-]{36}/credentials/ack",
                request.url.path,
            )
            or re.fullmatch(
                r"/internal/nodes/[0-9a-f-]{36}/telemetry",
                request.url.path,
            )
            or re.fullmatch(
                r"/internal/canaries/[0-9a-f-]{36}/checks",
                request.url.path,
            )
        )
        if request.method == "POST" and json_post:
            content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return error_response(
                    status_code=415,
                    code="UNSUPPORTED_MEDIA_TYPE",
                    message="Content-Type must be application/json",
                    request_id=request.state.request_id,
                )
        return await call_next(request)
