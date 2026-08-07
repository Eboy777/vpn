from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from vpn_service.http.responses import error_response


class RequestContractMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "POST" and request.url.path == "/api/pairing/init":
            content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return error_response(
                    status_code=415,
                    code="UNSUPPORTED_MEDIA_TYPE",
                    message="Content-Type must be application/json",
                    request_id=request.state.request_id,
                )
        return await call_next(request)
