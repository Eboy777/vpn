from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
from pydantic import TypeAdapter, ValidationError

from vpn_service.config import Settings


class LavaError(RuntimeError):
    """A safe provider error that does not expose response bodies or credentials."""


@dataclass(frozen=True, slots=True)
class CreatedLavaInvoice:
    contract_id: str
    status: str
    amount_minor: int
    currency: str
    payment_url: str
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LavaInvoiceDetails:
    contract_id: str
    status: str
    amount_minor: int
    currency: str
    offer_name: str | None
    subscription_expires_at: datetime | None
    raw: dict[str, Any]


class LavaClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        api_key = settings.effective_lava_api_key
        self._api_key = api_key.get_secret_value() if api_key is not None else None
        self._base_url = str(settings.lava_api_base_url).rstrip("/")
        self._timeout = settings.lava_request_timeout_seconds
        self._transport = transport

    async def create_invoice(
        self,
        *,
        offer_id: uuid.UUID,
        currency: str,
        periodicity: str,
        email: str | None,
    ) -> CreatedLavaInvoice:
        payload: dict[str, Any] = {
            "offerId": str(offer_id),
            "currency": currency,
            "periodicity": periodicity,
            "buyerLanguage": "RU",
        }
        if email is not None:
            payload["email"] = email
        data = await self._request("POST", "/api/v3/invoice", json=payload)
        try:
            contract_id = str(uuid.UUID(_required_string(data, "id")))
            status = _required_string(data, "status").lower()
            amount_total = data["amountTotal"]
            if not isinstance(amount_total, dict):
                raise ValueError
            currency_value = _required_string(amount_total, "currency")
            amount_minor = _amount_to_minor(amount_total["amount"])
            payment_url = _required_string(data, "paymentUrl")
            parsed_url = httpx.URL(payment_url)
            if parsed_url.scheme != "https" or parsed_url.host is None:
                raise ValueError
        except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
            raise LavaError("Lava returned an invalid invoice response") from exc
        if currency_value != currency:
            raise LavaError("Lava returned an unexpected invoice currency")
        return CreatedLavaInvoice(
            contract_id=contract_id,
            status=status,
            amount_minor=amount_minor,
            currency=currency_value,
            payment_url=payment_url,
            raw=data,
        )

    async def invoice(self, contract_id: str) -> LavaInvoiceDetails:
        canonical_id = str(uuid.UUID(contract_id))
        data = await self._request("GET", f"/api/v2/invoices/{canonical_id}")
        try:
            response_id = str(uuid.UUID(_required_string(data, "id")))
            status = _required_string(data, "status").lower()
            receipt = data["receipt"]
            if not isinstance(receipt, dict):
                raise ValueError
            amount_minor = _amount_to_minor(receipt["amount"])
            currency = _required_string(receipt, "currency")
            product = data.get("product")
            offer_name = product.get("offer") if isinstance(product, dict) else None
            if offer_name is not None and not isinstance(offer_name, str):
                raise ValueError
            subscription = data.get("subscriptionDetails")
            expires_value = (
                subscription.get("expiredAt") if isinstance(subscription, dict) else None
            )
            expires_at = (
                TypeAdapter(datetime).validate_python(expires_value)
                if expires_value is not None
                else None
            )
        except (KeyError, TypeError, ValueError, InvalidOperation, ValidationError) as exc:
            raise LavaError("Lava returned invalid invoice details") from exc
        if response_id != canonical_id:
            raise LavaError("Lava returned details for another invoice")
        return LavaInvoiceDetails(
            contract_id=response_id,
            status=status,
            amount_minor=amount_minor,
            currency=currency,
            offer_name=offer_name,
            subscription_expires_at=expires_at,
            raw=data,
        )

    async def cancel_subscription(self, contract_id: str, email: str) -> None:
        canonical_id = str(uuid.UUID(contract_id))
        await self._request(
            "DELETE",
            "/api/v1/subscriptions",
            params={"contractId": canonical_id, "email": email},
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if self._api_key is None:
            raise LavaError("Lava API is not configured")
        headers = {"Accept": "application/json", "X-Api-Key": self._api_key}
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = await client.request(
                    method,
                    path,
                    headers=headers,
                    json=json,
                    params=params,
                )
        except httpx.HTTPError as exc:
            raise LavaError("Lava API is unavailable") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise LavaError(f"Lava API rejected the request with HTTP {response.status_code}")
        if response.status_code == 204:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise LavaError("Lava returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise LavaError("Lava returned an invalid response")
        return data


def _required_string(data: dict[str, Any], key: str) -> str:
    value = data[key]
    if not isinstance(value, str) or not value:
        raise ValueError
    return value


def _amount_to_minor(value: object) -> int:
    amount = Decimal(str(value))
    minor = amount * 100
    if amount <= 0 or minor != minor.to_integral_value():
        raise ValueError
    return int(minor)
