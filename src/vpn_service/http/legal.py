from __future__ import annotations

import html
from pathlib import Path

from fastapi import APIRouter
from starlette.responses import HTMLResponse, Response

router = APIRouter(prefix="/legal", tags=["legal"])
_LEGAL_ROOT = Path(__file__).resolve().parents[1] / "assets" / "legal"
_DOCUMENTS = {
    "user-agreement": "USER_AGREEMENT.md",
    "privacy-policy": "PRIVACY_POLICY.md",
    "personal-data-consent": "PERSONAL_DATA_CONSENT.md",
    "recurring-payment-consent": "RECURRING_PAYMENT_CONSENT.md",
    "refund-and-cancellation": "REFUND_AND_CANCELLATION_POLICY.md",
}


@router.get("/{document}", response_class=HTMLResponse)
async def legal_document(document: str) -> Response:
    filename = _DOCUMENTS.get(document)
    if filename is None:
        return Response(status_code=404)
    path = _LEGAL_ROOT / filename
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return Response(status_code=503)
    title = next(
        (line.removeprefix("# ") for line in source.splitlines() if line.startswith("# ")),
        "Virgo",
    )
    body = html.escape(source)
    return HTMLResponse(
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{max-width:860px;margin:40px auto;padding:0 20px;background:#151515;"
        "color:#f4f4f4;font:16px/1.55 system-ui,sans-serif}pre{white-space:pre-wrap;"
        "font:inherit}a{color:#7ec8ff}</style></head><body>"
        f"<pre>{body}</pre></body></html>",
        headers={"Cache-Control": "public, max-age=300"},
    )
