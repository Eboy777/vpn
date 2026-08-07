from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
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
from vpn_service.persistence.models import Node, OutboxEvent, Payment, User
from vpn_service.worker.leader import WorkerAlreadyRunningError, WorkerLeader
from vpn_service.worker.outbox import OutboxWorker


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
        "devices",
        "node_auth_tokens",
        "node_check_events",
        "node_snapshot_acks",
        "nodes",
        "outbox_events",
        "payments",
        "telegram_update_events",
        "users",
    }
    assert "ck_nodes_port_range" in schema["nodes"]["checks"]
    assert "uq_payments_user_idempotency" in schema["payments"]["unique"]
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
                tariff_code="vpn_30d",
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
