from __future__ import annotations

import html
import re
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
    body = _render_markdown(source)
    return HTMLResponse(
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>:root{color-scheme:dark}body{max-width:860px;margin:0 auto;padding:42px 24px 64px;"
        "background:#151515;color:#f4f4f4;font:16px/1.65 system-ui,sans-serif}"
        "h1{margin:0 0 12px;font-size:32px;line-height:1.2}h2{margin:32px 0 10px;font-size:21px}"
        "p{margin:0 0 14px;color:#e8e8e8}ul{margin:0 0 18px;padding-left:24px}li+li{margin-top:6px}"
        "a{color:#7ec8ff}code{padding:2px 5px;border-radius:5px;background:#2b2b2b}"
        "@media(max-width:600px){body{padding:26px 18px 48px;font-size:15px}h1{font-size:27px}}"
        "</style></head><body>"
        f"{body}</body></html>",
        headers={"Cache-Control": "public, max-age=300"},
    )


def _render_markdown(source: str) -> str:
    blocks: list[str] = []
    paragraph: list[str] = []
    list_items: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append(f"<p>{_inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    def flush_list() -> None:
        if list_items:
            items = "".join(f"<li>{_inline(item)}</li>" for item in list_items)
            blocks.append(f"<ul>{items}</ul>")
            list_items.clear()

    for raw_line in source.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            flush_paragraph()
            flush_list()
            continue
        if raw_line.startswith("# "):
            flush_paragraph()
            flush_list()
            blocks.append(f"<h1>{_inline(raw_line[2:].strip())}</h1>")
            continue
        if raw_line.startswith("## "):
            flush_paragraph()
            flush_list()
            blocks.append(f"<h2>{_inline(raw_line[3:].strip())}</h2>")
            continue
        if raw_line.startswith("- "):
            flush_paragraph()
            list_items.append(raw_line[2:].strip())
            continue
        if list_items and raw_line[:1].isspace():
            list_items[-1] += " " + stripped
            continue
        flush_list()
        paragraph.append(stripped)

    flush_paragraph()
    flush_list()
    return "".join(blocks)


def _inline(value: str) -> str:
    escaped = html.escape(value)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(
        r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
        r'<a href="mailto:\1">\1</a>',
        escaped,
    )
    return escaped
