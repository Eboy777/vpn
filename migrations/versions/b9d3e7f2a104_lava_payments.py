"""Add Lava payment and webhook state.

Revision ID: b9d3e7f2a104
Revises: d5f7a9b3e206
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b9d3e7f2a104"
down_revision: str | Sequence[str] | None = "d5f7a9b3e206"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("payments", sa.Column("parent_external_payment_id", sa.String(128)))
    op.add_column("payments", sa.Column("lava_offer_id", sa.UUID()))
    op.add_column("payments", sa.Column("buyer_email", sa.String(320)))
    op.add_column("payments", sa.Column("periodicity", sa.String(32)))
    op.add_column("payments", sa.Column("subscription_status", sa.String(32)))
    op.add_column("payments", sa.Column("subscription_expires_at", sa.DateTime(timezone=True)))
    op.add_column("payments", sa.Column("terms_accepted_at", sa.DateTime(timezone=True)))
    op.add_column("payments", sa.Column("recurring_consent_at", sa.DateTime(timezone=True)))
    op.add_column("payments", sa.Column("consent_version", sa.String(32)))
    op.create_unique_constraint(
        "uq_payments_external_payment_id",
        "payments",
        ["external_payment_id"],
    )
    op.create_table(
        "payment_webhook_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("body_hash", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("contract_id", sa.String(128), nullable=False),
        sa.Column("result_code", sa.String(32), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "body_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_payment_webhook_events_body_hash_format"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_payment_webhook_events")),
        sa.UniqueConstraint(
            "body_hash",
            name="uq_payment_webhook_events_body_hash",
        ),
    )
    op.create_index(
        "ix_payment_webhook_events_contract",
        "payment_webhook_events",
        ["contract_id", "received_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_payment_webhook_events_contract", table_name="payment_webhook_events")
    op.drop_table("payment_webhook_events")
    op.drop_constraint("uq_payments_external_payment_id", "payments", type_="unique")
    op.drop_column("payments", "consent_version")
    op.drop_column("payments", "recurring_consent_at")
    op.drop_column("payments", "terms_accepted_at")
    op.drop_column("payments", "subscription_expires_at")
    op.drop_column("payments", "subscription_status")
    op.drop_column("payments", "periodicity")
    op.drop_column("payments", "buyer_email")
    op.drop_column("payments", "lava_offer_id")
    op.drop_column("payments", "parent_external_payment_id")
