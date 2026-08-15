from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.enums import PaymentStatus
from vpn_service.domain.errors import ApplicationError
from vpn_service.external.lava import CreatedLavaInvoice, LavaClient, LavaError
from vpn_service.http.schemas import LavaWebhookRequest
from vpn_service.persistence.models import Payment, PaymentWebhookEvent, User
from vpn_service.persistence.rate_limits import consume_rate_limit
from vpn_service.security.tokens import TokenHasher

_SUCCESS_EVENTS = {"payment.success", "subscription.recurring.payment.success"}
_FAILED_EVENTS = {"payment.failed", "subscription.recurring.payment.failed"}
_REPLAYABLE_WEBHOOK_RESULTS = {"provider_mismatch"}
_CONSENT_VERSION = "2026-08-15"


@dataclass(frozen=True, slots=True)
class PaymentCreateResult:
    payment_id: uuid.UUID
    contract_id: str
    payment_url: str
    tariff_code: str
    amount_minor: int
    currency: str
    periodicity: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class WebhookResult:
    result: str


class PaymentService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        lava: LavaClient | None = None,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._lava = lava or LavaClient(settings)
        self._tokens = TokenHasher(settings)

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        tariff_code: str,
        idempotency_key: str,
        email: str | None,
        terms_accepted: bool,
        recurring_consent: bool,
    ) -> PaymentCreateResult:
        tariff = self._settings.tariffs_json.get(tariff_code)
        offer = self._settings.lava_offers_json.get(tariff_code)
        if tariff is None or not tariff.enabled or offer is None:
            raise ApplicationError(409, "TARIFF_UNAVAILABLE", "Tariff is unavailable")
        if not self._settings.payments_production_enabled:
            raise ApplicationError(
                409,
                "PAYMENTS_NOT_LAUNCHED",
                "Продажи этого тарифа ещё не запущены",
            )
        if not terms_accepted:
            raise ApplicationError(400, "TERMS_NOT_ACCEPTED", "Terms must be accepted")
        recurring = offer.periodicity != "ONE_TIME"
        if recurring and not recurring_consent:
            raise ApplicationError(
                400,
                "RECURRING_CONSENT_REQUIRED",
                "Recurring payment consent is required",
            )

        request_hash = _request_hash(
            tariff_code=tariff_code,
            email=email,
            terms_accepted=terms_accepted,
            recurring_consent=recurring_consent,
        )
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            decision = await consume_rate_limit(
                session,
                scope="payment-create-minute",
                subject_hash=self._tokens.opaque_subject("payment-create", str(user_id)),
                limit=self._settings.payment_create_rate_per_minute,
                window_seconds=60,
                now=now,
            )
            if not decision.allowed:
                raise ApplicationError(
                    429,
                    "RATE_LIMITED",
                    "Too many payment attempts",
                    headers={"Retry-After": str(decision.retry_after)},
                )
            existing = await session.scalar(
                select(Payment)
                .where(
                    Payment.user_id == user_id,
                    Payment.idempotency_key == idempotency_key,
                )
                .with_for_update()
            )
            if existing is not None:
                if existing.idempotency_request_hash != request_hash:
                    raise ApplicationError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency key was already used for another request",
                    )
                return _result_from_payment(existing, replayed=True)

            user = await session.get(User, user_id)
            if user is None:
                raise ApplicationError(401, "INVALID_DEVICE_TOKEN", "Device token is invalid")
            try:
                created = await self._lava.create_invoice(
                    offer_id=offer.offer_id,
                    currency=tariff.currency,
                    periodicity=offer.periodicity,
                    email=email,
                )
            except LavaError as exc:
                raise ApplicationError(
                    503,
                    "PAYMENT_PROVIDER_UNAVAILABLE",
                    "Payment provider is unavailable",
                ) from exc
            payment = _new_payment(
                user_id=user_id,
                tariff_code=tariff_code,
                period_days=tariff.period_days,
                offer_id=offer.offer_id,
                periodicity=offer.periodicity,
                email=email,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                created=created,
                now=now,
                terms_accepted=terms_accepted,
                recurring_consent=recurring_consent,
            )
            session.add(payment)
            await session.flush()
            return _result_from_payment(payment, replayed=False)

    async def handle_webhook(
        self,
        *,
        payload: LavaWebhookRequest,
        raw_body: bytes,
    ) -> WebhookResult:
        body_hash = hashlib.sha256(raw_body).hexdigest()
        async with self._sessions.begin() as session:
            now = await _database_now(session)
            event_id = uuid.uuid4()
            inserted = (
                await session.execute(
                    insert(PaymentWebhookEvent)
                    .values(
                        id=event_id,
                        body_hash=body_hash,
                        event_type=payload.event_type,
                        contract_id=str(payload.contract_id),
                        result_code="processing",
                        payload_json=payload.model_dump(mode="json", by_alias=True),
                        received_at=now,
                    )
                    .on_conflict_do_nothing(index_elements=[PaymentWebhookEvent.body_hash])
                    .returning(PaymentWebhookEvent.id)
                )
            ).scalar_one_or_none()
            if inserted is None:
                event = await session.scalar(
                    select(PaymentWebhookEvent)
                    .where(PaymentWebhookEvent.body_hash == body_hash)
                    .with_for_update()
                )
                if event is None or event.result_code not in _REPLAYABLE_WEBHOOK_RESULTS:
                    return WebhookResult("duplicate")
                result_code = await self._apply_webhook(session, payload=payload, now=now)
                event.result_code = result_code
                return WebhookResult(result_code)
            result_code = await self._apply_webhook(session, payload=payload, now=now)
            event = await session.get(PaymentWebhookEvent, event_id)
            assert event is not None
            event.result_code = result_code
            return WebhookResult(result_code)

    async def cancel(self, *, user_id: uuid.UUID) -> bool:
        async with self._sessions.begin() as session:
            payment = await session.scalar(
                select(Payment)
                .where(
                    Payment.user_id == user_id,
                    Payment.status == PaymentStatus.PAID.value,
                    Payment.periodicity != "ONE_TIME",
                    Payment.parent_external_payment_id.is_(None),
                )
                .order_by(Payment.paid_at.desc())
                .limit(1)
                .with_for_update()
            )
            if payment is None:
                return False
            if payment.external_payment_id is None or payment.buyer_email is None:
                raise ApplicationError(
                    409,
                    "SUBSCRIPTION_CANNOT_BE_CANCELLED",
                    "Subscription is missing provider identity",
                )
            try:
                await self._lava.cancel_subscription(
                    payment.external_payment_id,
                    payment.buyer_email,
                )
            except LavaError as exc:
                raise ApplicationError(
                    503,
                    "PAYMENT_PROVIDER_UNAVAILABLE",
                    "Payment provider is unavailable",
                ) from exc
            payment.subscription_status = "cancellation_requested"
            return True

    async def _apply_webhook(
        self,
        session: AsyncSession,
        *,
        payload: LavaWebhookRequest,
        now: datetime,
    ) -> str:
        if (
            self._settings.lava_product_id is not None
            and payload.product.id != self._settings.lava_product_id
        ):
            return "product_ignored"

        contract_id = str(payload.contract_id)
        parent_id = str(payload.parent_contract_id) if payload.parent_contract_id else None
        payment = await session.scalar(
            select(Payment).where(Payment.external_payment_id == contract_id).with_for_update()
        )
        parent = None
        if parent_id is not None:
            parent = await session.scalar(
                select(Payment).where(Payment.external_payment_id == parent_id).with_for_update()
            )
        if payment is None and parent is None:
            return "contract_ignored"

        if payload.event_type == "subscription.cancelled":
            target = parent or payment
            assert target is not None
            target.subscription_status = "cancelled"
            return "cancelled"

        if payload.event_type in _FAILED_EVENTS:
            target = payment
            if target is None and parent is not None:
                target = _new_recurring_payment(parent, payload=payload, now=now)
                session.add(target)
            assert target is not None
            if target.status != PaymentStatus.PAID.value:
                target.status = PaymentStatus.FAILED.value
            if parent is not None:
                parent.subscription_status = "payment_failed"
            return "failed"

        if payload.event_type not in _SUCCESS_EVENTS:
            return "event_ignored"

        if payment is not None and payment.status == PaymentStatus.PAID.value:
            return "duplicate"

        if payment is None:
            assert parent is not None
            payment = _new_recurring_payment(parent, payload=payload, now=now)
            session.add(payment)
        expected_currency = (
            payment.create_response_json.get("amountTotal", {}).get("currency")
            if payment.create_response_json
            else payload.currency
        )
        if payload.currency != expected_currency:
            return "amount_mismatch"
        webhook_amount_minor = _amount_to_minor(payload.amount)
        if payment.amount_minor != webhook_amount_minor:
            return "amount_mismatch"

        try:
            details = await self._lava.invoice(contract_id)
        except LavaError as exc:
            raise ApplicationError(
                503,
                "PAYMENT_PROVIDER_UNAVAILABLE",
                "Payment provider is unavailable",
            ) from exc
        if (
            details.currency != payload.currency
            or details.amount_minor != webhook_amount_minor
            or details.status not in {"completed", "subscription-active"}
        ):
            return "provider_mismatch"

        user = await session.scalar(
            select(User).where(User.id == payment.user_id).with_for_update()
        )
        if user is None:
            return "user_ignored"
        payment.status = PaymentStatus.PAID.value
        payment.paid_at = payload.timestamp.astimezone(UTC)
        payment.buyer_email = payload.buyer.email
        payment.subscription_status = "active" if payment.periodicity != "ONE_TIME" else None
        payment.subscription_expires_at = details.subscription_expires_at
        base = max(now, user.subscription_expires_at or now)
        expires_at = details.subscription_expires_at or base + timedelta(days=payment.period_days)
        if expires_at > (user.subscription_expires_at or now):
            user.subscription_expires_at = expires_at
        if parent is not None:
            parent.subscription_status = "active"
            parent.subscription_expires_at = expires_at
        return "paid"


def _new_payment(
    *,
    user_id: uuid.UUID,
    tariff_code: str,
    period_days: int,
    offer_id: uuid.UUID,
    periodicity: str,
    email: str | None,
    idempotency_key: str,
    request_hash: str,
    created: CreatedLavaInvoice,
    now: datetime,
    terms_accepted: bool,
    recurring_consent: bool,
) -> Payment:
    return Payment(
        id=uuid.uuid4(),
        user_id=user_id,
        invoice_id=str(uuid.uuid4()),
        external_payment_id=created.contract_id,
        parent_external_payment_id=None,
        lava_offer_id=offer_id,
        buyer_email=email,
        periodicity=periodicity,
        subscription_status="pending" if periodicity != "ONE_TIME" else None,
        subscription_expires_at=None,
        tariff_code=tariff_code,
        amount_minor=created.amount_minor,
        period_days=period_days,
        status=PaymentStatus.CREATED.value,
        webhook_hash=None,
        idempotency_key=idempotency_key,
        idempotency_request_hash=request_hash,
        create_response_json=created.raw,
        paid_at=None,
        terms_accepted_at=now if terms_accepted else None,
        recurring_consent_at=now if recurring_consent else None,
        consent_version=_CONSENT_VERSION,
        created_at=now,
    )


def _new_recurring_payment(
    parent: Payment,
    *,
    payload: LavaWebhookRequest,
    now: datetime,
) -> Payment:
    contract_id = str(payload.contract_id)
    return Payment(
        id=uuid.uuid4(),
        user_id=parent.user_id,
        invoice_id=contract_id,
        external_payment_id=contract_id,
        parent_external_payment_id=parent.external_payment_id,
        lava_offer_id=parent.lava_offer_id,
        buyer_email=payload.buyer.email,
        periodicity=parent.periodicity,
        subscription_status=None,
        subscription_expires_at=None,
        tariff_code=parent.tariff_code,
        amount_minor=_amount_to_minor(payload.amount),
        period_days=parent.period_days,
        status=PaymentStatus.CREATED.value,
        webhook_hash=None,
        idempotency_key=None,
        idempotency_request_hash=None,
        create_response_json=None,
        paid_at=None,
        terms_accepted_at=parent.terms_accepted_at,
        recurring_consent_at=parent.recurring_consent_at,
        consent_version=parent.consent_version,
        created_at=now,
    )


def _result_from_payment(payment: Payment, *, replayed: bool) -> PaymentCreateResult:
    response = payment.create_response_json or {}
    payment_url = response.get("paymentUrl")
    if payment.external_payment_id is None or not isinstance(payment_url, str):
        raise ApplicationError(
            503,
            "PAYMENT_PROVIDER_UNAVAILABLE",
            "Payment link is unavailable",
        )
    currency = response.get("amountTotal", {}).get("currency")
    if not isinstance(currency, str) or payment.periodicity is None:
        raise ApplicationError(503, "PAYMENT_PROVIDER_UNAVAILABLE", "Payment is invalid")
    return PaymentCreateResult(
        payment_id=payment.id,
        contract_id=payment.external_payment_id,
        payment_url=payment_url,
        tariff_code=payment.tariff_code,
        amount_minor=payment.amount_minor,
        currency=currency,
        periodicity=payment.periodicity,
        replayed=replayed,
    )


def _request_hash(
    *,
    tariff_code: str,
    email: str | None,
    terms_accepted: bool,
    recurring_consent: bool,
) -> str:
    body = json.dumps(
        {
            "email": email,
            "recurring_consent": recurring_consent,
            "tariff_code": tariff_code,
            "terms_accepted": terms_accepted,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(body).hexdigest()


def _amount_to_minor(value: Decimal) -> int:
    minor = value * 100
    if value <= 0 or minor != minor.to_integral_value():
        raise ApplicationError(400, "INVALID_WEBHOOK", "Webhook amount is invalid")
    return int(minor)


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value
