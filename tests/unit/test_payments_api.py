from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest

from vpn_service.app import create_app
from vpn_service.application.device_auth import AuthenticatedDevice
from vpn_service.application.payments import PaymentCreateResult, WebhookResult
from vpn_service.config import Settings
from vpn_service.security.telegram_payment_links import TelegramPaymentLinkSigner


async def _database_probe() -> bool:
    return True


class FakeAuthenticator:
    async def authenticate(self, _token: str, *, source_ip: str | None = None):
        return AuthenticatedDevice(
            device_row_id=uuid.UUID("00000000-0000-4000-8000-000000000001"),
            device_id=uuid.UUID("00000000-0000-4000-8000-000000000002"),
            user_id=uuid.UUID("00000000-0000-4000-8000-000000000003"),
        )


class FakePayments:
    async def create(self, **kwargs):
        assert kwargs["tariff_code"] == "flow_1m"
        assert kwargs["terms_accepted"] is True
        return PaymentCreateResult(
            payment_id=uuid.UUID("00000000-0000-4000-8000-000000000004"),
            contract_id="7ea82675-4ded-4133-95a7-a6efbaf165cc",
            payment_url="https://app.lava.top/payment/test",
            tariff_code="flow_1m",
            amount_minor=29_900,
            currency="RUB",
            periodicity="MONTHLY",
            replayed=False,
        )

    async def handle_webhook(self, **kwargs):
        assert kwargs["payload"].amount == Decimal("299")
        return WebhookResult("paid")

    async def create_for_telegram(self, **kwargs):
        assert kwargs["telegram_id"] == 123456789
        assert kwargs["tariff_code"] == "flow_1m"
        return await self.create(
            tariff_code=kwargs["tariff_code"],
            terms_accepted=True,
        )

    async def cancel(self, **kwargs):
        assert kwargs["user_id"] == uuid.UUID("00000000-0000-4000-8000-000000000003")
        return True


@pytest.fixture
async def payment_client(
    settings_factory: Callable[..., Settings],
) -> AsyncIterator[httpx.AsyncClient]:
    settings = settings_factory(lava_webhook_api_key="webhook-secret")
    app = create_app(settings, database_probe=_database_probe)
    app.state.device_authenticator = FakeAuthenticator()
    app.state.payment_service = FakePayments()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_create_payment_contract(payment_client: httpx.AsyncClient) -> None:
    response = await payment_client.post(
        "/api/payments/create",
        headers={
            "Authorization": "Bearer " + "a" * 43,
            "Idempotency-Key": "test-payment-key-0001",
        },
        json={
            "tariff_code": "flow_1m",
            "email": "client@example.com",
            "terms_accepted": True,
            "recurring_consent": True,
        },
    )

    assert response.status_code == 201
    assert response.json()["contract_id"] == "7ea82675-4ded-4133-95a7-a6efbaf165cc"
    assert response.json()["payment_url"].startswith("https://app.lava.top/")


@pytest.mark.asyncio
async def test_telegram_payment_link_redirects_directly_to_lava(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(lava_webhook_api_key="webhook-secret")
    app = create_app(settings, database_probe=_database_probe)
    app.state.payment_service = FakePayments()
    token = TelegramPaymentLinkSigner(settings).issue(
        telegram_id=123456789,
        tariff_code="flow_1m",
        now=datetime.now(UTC),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        follow_redirects=False,
    ) as client:
        response = await client.get(f"/api/payments/telegram/{token}")

    assert response.status_code == 303
    assert response.headers["location"] == "https://app.lava.top/payment/test"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_lava_webhook_requires_key_and_accepts_schema(
    payment_client: httpx.AsyncClient,
) -> None:
    payload = {
        "eventType": "payment.success",
        "product": {
            "id": "12029037-7fb7-4f72-b048-8c3412247569",
            "title": "Virgo",
        },
        "contractId": "7ea82675-4ded-4133-95a7-a6efbaf165cc",
        "parentContractId": None,
        "buyer": {"email": "client@example.com"},
        "amount": 299,
        "currency": "RUB",
        "status": "subscription-active",
        "timestamp": datetime(2026, 8, 15, tzinfo=UTC).isoformat(),
        "errorMessage": "",
    }
    denied = await payment_client.post("/api/payments/lava/webhook/payment", json=payload)
    accepted = await payment_client.post(
        "/api/payments/lava/webhook/payment",
        headers={"X-Api-Key": "webhook-secret"},
        json=payload,
    )

    assert denied.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json() == {"result": "paid"}


@pytest.mark.asyncio
async def test_lava_recurring_webhook_uses_same_strict_contract(
    payment_client: httpx.AsyncClient,
) -> None:
    payload = {
        "eventType": "subscription.recurring.payment.success",
        "product": {
            "id": "12029037-7fb7-4f72-b048-8c3412247569",
            "title": "Virgo",
        },
        "contractId": "8ea82675-4ded-4133-95a7-a6efbaf165cc",
        "parentContractId": "7ea82675-4ded-4133-95a7-a6efbaf165cc",
        "buyer": {"email": "client@example.com"},
        "amount": 299,
        "currency": "RUB",
        "status": "subscription-active",
        "timestamp": datetime(2026, 9, 15, tzinfo=UTC).isoformat(),
        "errorMessage": "",
    }
    response = await payment_client.post(
        "/api/payments/lava/webhook/recurring",
        headers={"X-Api-Key": "webhook-secret"},
        json=payload,
    )

    assert response.status_code == 200
    assert response.json() == {"result": "paid"}


@pytest.mark.asyncio
async def test_cancel_subscription_contract(payment_client: httpx.AsyncClient) -> None:
    response = await payment_client.post(
        "/api/payments/subscription/cancel",
        headers={"Authorization": "Bearer " + "a" * 43},
    )

    assert response.status_code == 200
    assert response.json() == {"cancelled": True}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_legal_document_is_public(payment_client: httpx.AsyncClient) -> None:
    response = await payment_client.get("/legal/user-agreement")

    assert response.status_code == 200
    assert "Пользовательское соглашение" in response.text
    assert "<h1>Пользовательское соглашение" in response.text
    assert "**[" not in response.text
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.asyncio
async def test_unknown_legal_document_is_not_exposed(payment_client: httpx.AsyncClient) -> None:
    response = await payment_client.get("/legal/not-a-document")

    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "document",
    [
        "user-agreement",
        "privacy-policy",
        "personal-data-consent",
        "recurring-payment-consent",
        "refund-and-cancellation",
    ],
)
async def test_legal_documents_have_no_draft_placeholders(
    payment_client: httpx.AsyncClient,
    document: str,
) -> None:
    response = await payment_client.get(f"/legal/{document}")

    assert response.status_code == 200
    for marker in ("**[", "[ФИО", "[ИНН", "[адрес", "[URL", "[заполнить"):
        assert marker not in response.text
