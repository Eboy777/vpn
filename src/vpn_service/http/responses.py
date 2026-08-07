from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse


class ContractJSONResponse(JSONResponse):
    media_type = "application/json; charset=utf-8"


def no_store_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    result = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    if headers:
        result.update(headers)
    return result


def error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> ContractJSONResponse:
    return ContractJSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
                "details": details or [],
            }
        },
        headers=no_store_headers(headers),
    )
