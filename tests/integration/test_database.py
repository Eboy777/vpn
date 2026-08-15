from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vpn_service.config import Settings
from vpn_service.domain.enums import OutboxStatus
from vpn_service.persistence.database import Database
from vpn_service.persistence.models import (
    Node,
    NodeSnapshotIssue,
    OutboxEvent,
    Payment,
    RateLimitCounter,
    User,
)
from vpn_service.worker.leader import WorkerAlreadyRunningError, WorkerLeader
from vpn_service.worker.outbox import OutboxWorker
from vpn_service.worker.rate_limits import RateLimitPruner
from vpn_service.worker.snapshot_issues import SnapshotIssuePruner


def database_url() -> str:
    value = os.environ.get("TEST_DATABASE_URL")
    if not value:
        pytest.skip("TEST_DATABASE_URL is not configured")
    return value


def alembic_config() -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url().replace("%", "%%"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> Iterator[str]:
    url = database_url()
    command.upgrade(alembic_config(), "head")
    yield url


@pytest.fixture
async def engine(migrated_database: str) -> AsyncIterator[AsyncEngine]:
    created = create_async_engine(migrated_database, pool_pre_ping=True)
    yield created
    await created.dispose()


@pytest.mark.integration
def test_migration_upgrade_downgrade_upgrade_cycle() -> None:
    config = alembic_config()

    command.upgrade(config, "head")
    command.downgrade(config, "base")
    command.upgrade(config, "head")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_database_constraints_and_utc_defaults(engine: AsyncEngine) -> None:
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with sessions() as session:
        invalid = Node(
            name=f"invalid-{uuid.uuid4()}",
            host="invalid.example.test",
            port=70_000,
            country_code="NL",
            provider="test",
            capacity_users=10,
        )
        session.add(invalid)
        with pytest.raises(IntegrityError):
            await session.commit()

    async with sessions() as session:
        node = Node(
            name=f"node-{uuid.uuid4()}",
            host="nl-1.example.test",
            port=443,
            country_code="NL",
            provider="test",
            capacity_users=10,
        )
        session.add(node)
        await session.commit()
        await session.refresh(node)

        assert node.created_at.tzinfo is not None
        assert node.created_at.astimezone(UTC).utcoffset().total_seconds() == 0

    username = f"u_{uuid.uuid4().hex[:26]}"
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 1_000_000_000
    async with sessions() as session:
        session.add(
            User(
                telegram_id=telegram_id,
                proxy_username=username,
                proxy_password_ciphertext=b"ciphertext-envelope",
                proxy_password_key_id="v1",
            )
        )
        await session.commit()

    async with sessions() as session:
        session.add(
            User(
                telegram_id=telegram_id + 1,
                proxy_username=username.upper(),
                proxy_password_ciphertext=b"another-ciphertext-envelope",
                proxy_password_key_id="v1",
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_schema_has_named_constraints_and_indexes(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        schema = await connection.run_sync(_inspect_schema)

    assert set(schema) == {
        "alembic_version",
        "canaries",
        "canary_auth_tokens",
        "canary_runs",
        "control_ingresses",
        "devices",
        "extension_installations",
        "extension_lifecycle_events",
        "node_auth_tokens",
        "node_check_events",
        "node_runtime_metrics",
        "node_snapshot_acks",
        "node_snapshot_issues",
        "node_telemetry_reports",
        "node_user_traffic",
        "nodes",
        "outbox_events",
        "payment_webhook_events",
        "payments",
        "rate_limit_counters",
        "telegram_update_events",
        "user_activity_events",
        "users",
        "vpn_sessions",
    }
    assert "ck_nodes_port_range" in schema["nodes"]["checks"]
    assert "uq_payments_user_idempotency" in schema["payments"]["unique"]
    assert "uq_payments_external_payment_id" in schema["payments"]["unique"]
    assert "uq_payment_webhook_events_body_hash" in schema["payment_webhook_events"]["unique"]
    assert "uq_users_proxy_username_lower" in schema["users"]["indexes"]
    assert "ix_outbox_claim" in schema["outbox_events"]["indexes"]
    assert all(
        name
        for table in schema.values()
        for group in ("checks", "unique", "foreign_keys", "indexes")
        for name in table[group]
    )


def _inspect_schema(sync_connection: Connection) -> dict[str, dict[str, set[str]]]:
    inspector = inspect(sync_connection)
    result: dict[str, dict[str, set[str]]] = {}
    for table_name in inspector.get_table_names():
        result[table_name] = {
            "checks": {item["name"] for item in inspector.get_check_constraints(table_name)},
            "unique": {item["name"] for item in inspector.get_unique_constraints(table_name)},
            "foreign_keys": {item["name"] for item in inspector.get_foreign_keys(table_name)},
            "indexes": {item["name"] for item in inspector.get_indexes(table_name)},
        }
    return result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_payment_and_outbox_invariants(
    engine: AsyncEngine,
    migrated_database: str,
    settings_factory: Callable[..., Settings],
) -> None:
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    user = User(
        telegram_id=uuid.uuid4().int % 8_000_000_000 + 1_000_000_000,
        proxy_username=f"u_{uuid.uuid4().hex[:26]}",
        proxy_password_ciphertext=b"ciphertext-envelope",
        proxy_password_key_id="v1",
    )
    async with sessions() as session:
        session.add(user)
        await session.commit()

    async with sessions() as session:
        session.add(
            Payment(
                user_id=user.id,
                invoice_id=uuid.uuid4().hex,
                tariff_code="flow_1m",
                amount_minor=-1,
                period_days=30,
                idempotency_key=str(uuid.uuid4()),
                idempotency_request_hash="a" * 64,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()

    settings = settings_factory(database_url=migrated_database)
    database = Database(settings)
    event = OutboxEvent(
        event_type="unknown.stage-one.event",
        aggregate_type="test",
        idempotency_key=str(uuid.uuid4()),
        payload_json={"safe": True},
    )
    try:
        async with database.sessions() as session:
            session.add(event)
            await session.commit()
        assert await OutboxWorker(database.sessions, settings).process_one() is True
        async with database.sessions() as session:
            stored = await session.get(OutboxEvent, event.id)
            assert stored is not None
            assert stored.status == OutboxStatus.FAILED.value
            assert stored.attempts == 1
            assert stored.last_error_code == "UNSUPPORTED_EVENT_TYPE"
    finally:
        await database.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_only_one_worker_can_hold_scheduler_lock(engine: AsyncEngine) -> None:
    async with WorkerLeader(engine):
        with pytest.raises(WorkerAlreadyRunningError):
            async with WorkerLeader(engine):
                pass

    async with WorkerLeader(engine):
        pass


@pytest.mark.integration
@pytest.mark.asyncio
async def test_rate_limit_pruner_removes_only_expired_windows(
    engine: AsyncEngine,
    migrated_database: str,
    settings_factory: Callable[..., Settings],
) -> None:
    now = datetime(2026, 8, 7, 12, tzinfo=UTC)
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    suffix = uuid.uuid4().bytes
    async with sessions.begin() as session:
        session.add_all(
            [
                RateLimitCounter(
                    scope="pruner-test-old",
                    subject_hash=suffix + suffix,
                    window_start=now - timedelta(hours=3),
                    request_count=1,
                ),
                RateLimitCounter(
                    scope="pruner-test-current",
                    subject_hash=suffix + suffix,
                    window_start=now - timedelta(minutes=30),
                    request_count=1,
                ),
            ]
        )

    settings = settings_factory(database_url=migrated_database)
    removed = await RateLimitPruner(sessions, settings, clock=lambda: now).prune_once()

    async with sessions() as session:
        current = await session.get(
            RateLimitCounter,
            {
                "scope": "pruner-test-current",
                "subject_hash": suffix + suffix,
                "window_start": now - timedelta(minutes=30),
            },
        )
    assert removed >= 1
    assert current is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_snapshot_issue_pruner_keeps_recent_lease_history(
    engine: AsyncEngine,
    migrated_database: str,
    settings_factory: Callable[..., Settings],
) -> None:
    now = datetime(2026, 8, 7, 12, tzinfo=UTC)
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    old_revision = uuid.uuid4().hex + uuid.uuid4().hex
    recent_revision = uuid.uuid4().hex + uuid.uuid4().hex
    async with sessions.begin() as session:
        node_id = await session.scalar(select(Node.id).limit(1))
        assert node_id is not None
        session.add_all(
            [
                NodeSnapshotIssue(
                    node_id=node_id,
                    revision=old_revision,
                    snapshot_valid_until=now - timedelta(days=2),
                    issued_at=now - timedelta(days=2),
                ),
                NodeSnapshotIssue(
                    node_id=node_id,
                    revision=recent_revision,
                    snapshot_valid_until=now - timedelta(hours=1),
                    issued_at=now - timedelta(hours=1),
                ),
            ]
        )

    settings = settings_factory(
        database_url=migrated_database,
        node_snapshot_issue_retention_seconds=86_400,
    )
    removed = await SnapshotIssuePruner(sessions, settings, clock=lambda: now).prune_once()
    async with sessions() as session:
        recent = await session.scalar(
            select(NodeSnapshotIssue).where(NodeSnapshotIssue.revision == recent_revision)
        )
    assert removed >= 1
    assert recent is not None
