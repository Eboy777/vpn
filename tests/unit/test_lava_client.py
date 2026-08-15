from __future__ import annotations

import json
import uuid
from collections.abc import Callable

import httpx
import pytest

from vpn_service.config import Settings
from vpn_service.external.lava import LavaClient, LavaError


@pytest.mark.asyncio
async def test_lava_creates_invoice_without_exposing_api_key(
    settings_factory: Callable[..., Settings],
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["api_key"] = request.headers["X-Api-Key"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "id": "7ea82675-4ded-4133-95a7-a6efbaf165cc",
                "status": "new",
                "amountTotal": {"currency": "RUB", "amount": 299},
                "paymentUrl": "https://app.lava.top/payment/test",
            },
        )

    settings = settings_factory(lava_api_key="lava-secret")
    client = LavaClient(settings, transport=httpx.MockTransport(handler))
    invoice = await client.create_invoice(
        offer_id=uuid.UUID("d6a4c96c-157f-44fc-b175-dbb9026bde60"),
        currency="RUB",
        periodicity="MONTHLY",
        email="client@example.com",
    )

    assert invoice.amount_minor == 29_900
    assert invoice.payment_url.startswith("https://app.lava.top/")
    assert captured["api_key"] == "lava-secret"
    assert captured["body"] == {
        "email": "client@example.com",
        "offerId": "d6a4c96c-157f-44fc-b175-dbb9026bde60",
        "currency": "RUB",
        "periodicity": "MONTHLY",
        "buyerLanguage": "RU",
    }


@pytest.mark.asyncio
async def test_lava_rejects_non_https_payment_url(
    settings_factory: Callable[..., Settings],
) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            201,
            json={
                "id": "7ea82675-4ded-4133-95a7-a6efbaf165cc",
                "status": "new",
                "amountTotal": {"currency": "RUB", "amount": 299},
                "paymentUrl": "http://attacker.example/payment",
            },
        )
    )
    client = LavaClient(
        settings_factory(lava_api_key="lava-secret"),
        transport=transport,
    )

    with pytest.raises(LavaError, match="invalid invoice response"):
        await client.create_invoice(
            offer_id=uuid.UUID("d6a4c96c-157f-44fc-b175-dbb9026bde60"),
            currency="RUB",
            periodicity="MONTHLY",
            email="client@example.com",
        )


@pytest.mark.asyncio
async def test_lava_normalizes_uppercase_invoice_status(
    settings_factory: Callable[..., Settings],
) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            json={
                "id": "7ea82675-4ded-4133-95a7-a6efbaf165cc",
                "status": "COMPLETED",
                "receipt": {"currency": "RUB", "amount": 299},
                "product": {"offer": "Virgo FLOW"},
            },
        )
    )
    client = LavaClient(
        settings_factory(lava_api_key="lava-secret"),
        transport=transport,
    )

    invoice = await client.invoice("7ea82675-4ded-4133-95a7-a6efbaf165cc")

    assert invoice.status == "completed"
