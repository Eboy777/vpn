from __future__ import annotations

from collections.abc import Iterable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from vpn_service.http.responses import error_response

_PATH_METHODS = {
    "/api/pairing/init": "POST",
    "/api/pairing/status": "GET",
}
_ALLOWED_HEADERS = {"authorization", "content-type", "idempotency-key", "x-request-id"}
_ALLOW_HEADERS_VALUE = "Authorization, Content-Type, Idempotency-Key, X-Request-ID"
_EXPOSE_HEADERS = "X-Request-ID, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining"


class ExtensionCorsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, allowed_origins: Iterable[str]) -> None:
        super().__init__(app)
        self._allowed_origins = frozenset(allowed_origins)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        origin = request.headers.get("origin")
        if request.method == "OPTIONS" and request.url.path in _PATH_METHODS:
            return self._preflight(request, origin)

        response = await call_next(request)
        if origin in self._allowed_origins and request.url.path in _PATH_METHODS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Expose-Headers"] = _EXPOSE_HEADERS
            _append_vary(response, ["Origin"])
        return response

    def _preflight(self, request: Request, origin: str | None) -> Response:
        if origin not in self._allowed_origins:
            return error_response(
                status_code=403,
                code="CORS_ORIGIN_DENIED",
                message="CORS origin is not allowed",
                request_id=request.state.request_id,
            )
        requested_method = request.headers.get("access-control-request-method", "")
        requested_headers = {
            value.strip().lower()
            for value in request.headers.get("access-control-request-headers", "").split(",")
            if value.strip()
        }
        if requested_method != _PATH_METHODS[request.url.path] or not requested_headers.issubset(
            _ALLOWED_HEADERS
        ):
            return error_response(
                status_code=400,
                code="CORS_PREFLIGHT_INVALID",
                message="CORS preflight is invalid",
                request_id=request.state.request_id,
            )
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": _ALLOW_HEADERS_VALUE,
                "Access-Control-Max-Age": "600",
                "Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            },
        )


def _append_vary(response: Response, values: list[str]) -> None:
    existing = [value.strip() for value in response.headers.get("Vary", "").split(",") if value]
    response.headers["Vary"] = ", ".join(dict.fromkeys([*existing, *values]))
