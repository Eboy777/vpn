from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select

from vpn_service.app import create_app
from vpn_service.config import Settings
from vpn_service.domain.errors import ApplicationError
from vpn_service.persistence.models import Device, Node, OutboxEvent, TelegramUpdateEvent, User
from vpn_service.security.credentials import ProxyCredentialsCipher
from vpn_service.security.tokens import TokenHasher


def database_url() -> str:
    import os

    value = os.environ.get("TEST_DATABASE_URL")
    if not value:
        pytest.skip("TEST_DATABASE_URL is not configured")
    return value


@pytest.fixture(scope="module", autouse=True)
def migrated_database() -> str:
    url = database_url()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(config, "head")
    return url


@pytest.fixture
async def pairing_client(
    settings_factory: Callable[..., Settings],
    migrated_database: str,
) -> AsyncIterator[tuple[httpx.AsyncClient, object, Settings]]:
    settings = settings_factory(
        database_url=migrated_database,
        pairing_init_rate_per_minute=100,
        pairing_init_rate_per_hour=100,
        pairing_status_rate_per_minute=100,
        allowed_extension_origins_json=["chrome-extension://abcdefghijklmnopabcdefghijklmnop"],
    )
    app = create_app(settings)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )
    try:
        yield client, app, settings
    finally:
        await client.aclose()
        await app.state.database.dispose()


async def initialize(client: httpx.AsyncClient, device_id: uuid.UUID) -> dict[str, object]:
    response = await client.post("/api/pairing/init", json={"device_id": str(device_id)})
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def start_token(pairing: dict[str, object]) -> str:
    value = parse_qs(urlparse(str(pairing["telegram_url"])).query)["start"][0]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
    return value


def telegram_update(update_id: int, telegram_id: int, token: str, *, text: str | None = None):
    actual_text = text or f"/start {token}"
    return {
        "update_id": update_id,
        "message": {
            "message_id": update_id,
            "date": 1_785_986_120,
            "from": {"id": telegram_id, "is_bot": False, "first_name": "Test"},
            "chat": {"id": telegram_id, "type": "private"},
            "text": actual_text,
            "entities": [{"type": "bot_command", "offset": 0, "length": 6}],
        },
    }


async def bind(
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    update_id: int,
    telegram_id: int,
    token: str,
) -> httpx.Response:
    return await client.post(
        "/integrations/telegram/webhook/"
        + settings.telegram_webhook_path_secret.get_secret_value(),  # type: ignore[union-attr]
        headers={
            "X-Telegram-Bot-Api-Secret-Token": (
                settings.telegram_webhook_secret.get_secret_value()  # type: ignore[union-attr]
            )
        },
        json=telegram_update(update_id, telegram_id, token),
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_first_pairing_creates_one_trial_and_rotates_device_token(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = pairing_client
    node_id = uuid.uuid4()
    async with app.state.database.sessions.begin() as session:
        session.add(
            Node(
                id=node_id,
                name=f"NL-{uuid.uuid4()}",
                host="nl-stage-two.example.test",
                port=443,
                country_code="NL",
                provider="test",
                status="active",
                capacity_users=100,
            )
        )

    device_id = uuid.uuid4()
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 1_000_000_000
    created_before = datetime.now(UTC)
    pairing = await initialize(client, device_id)
    session_token = str(pairing["pairing_session_token"])
    token = start_token(pairing)
    assert token != session_token

    pending = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert pending.status_code == 202
    assert pending.json()["status"] == "pending"
    assert pending.headers["retry-after"] == "2"

    webhook = await bind(
        client,
        settings,
        update_id=uuid.uuid4().int % 2_000_000_000,
        telegram_id=telegram_id,
        token=token,
    )
    assert webhook.status_code == 200
    assert webhook.content == b""

    first_status = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    second_status = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert first_status.status_code == second_status.status_code == 200
    first_device_token = first_status.json()["device_token"]
    second_device_token = second_status.json()["device_token"]
    assert first_device_token != second_device_token

    with pytest.raises(ApplicationError, match="INVALID_DEVICE_TOKEN"):
        await app.state.device_authenticator.authenticate(first_device_token)
    authenticated = await app.state.device_authenticator.authenticate(second_device_token)
    assert authenticated.device_id == device_id
    consumed_session = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert consumed_session.status_code == 401

    async with app.state.database.sessions() as session:
        user = (
            await session.execute(select(User).where(User.telegram_id == telegram_id))
        ).scalar_one()
        device = (
            await session.execute(select(Device).where(Device.device_id == device_id))
        ).scalar_one()
        assert user.trial_expires_at is not None
        assert timedelta(hours=23, minutes=59) < user.trial_expires_at - created_before
        assert user.assigned_node_id is not None
        assert device.status == "active"
        assert device.telegram_start_token_hash is None
        assert device.pairing_session_token_hash is None
        hasher = TokenHasher(settings)
        assert device.device_token_hash == hasher.digest(
            "device",
            device.device_token_key_id,
            second_device_token,  # type: ignore[arg-type]
        )
        assert device.device_token_hash != hasher.digest(
            "device",
            device.device_token_key_id,
            first_device_token,  # type: ignore[arg-type]
        )
        password = ProxyCredentialsCipher(settings).decrypt(
            user.id,
            user.proxy_password_ciphertext,
        )
        assert re.fullmatch(r"[A-Za-z0-9_-]{32}", password)
        assert password.encode() not in user.proxy_password_ciphertext


@pytest.mark.integration
@pytest.mark.asyncio
async def test_replay_and_second_device_do_not_create_second_user_or_trial(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = pairing_client
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 1_000_000_000
    first_id, second_id = uuid.uuid4(), uuid.uuid4()
    first_pairing = await initialize(client, first_id)
    update_id = uuid.uuid4().int % 2_000_000_000
    response = await bind(
        client,
        settings,
        update_id=update_id,
        telegram_id=telegram_id,
        token=start_token(first_pairing),
    )
    assert response.status_code == 200

    async with app.state.database.sessions() as session:
        original = (
            await session.execute(select(User).where(User.telegram_id == telegram_id))
        ).scalar_one()
        original_values = (
            original.id,
            original.trial_expires_at,
            original.proxy_username,
            original.proxy_password_ciphertext,
        )

    replay = await bind(
        client,
        settings,
        update_id=update_id,
        telegram_id=telegram_id,
        token=start_token(first_pairing),
    )
    reused = await bind(
        client,
        settings,
        update_id=update_id + 1,
        telegram_id=telegram_id,
        token=start_token(first_pairing),
    )
    assert replay.status_code == reused.status_code == 200

    second_pairing = await initialize(client, second_id)
    second_bind = await bind(
        client,
        settings,
        update_id=update_id + 2,
        telegram_id=telegram_id,
        token=start_token(second_pairing),
    )
    assert second_bind.status_code == 200

    async with app.state.database.sessions() as session:
        users = list(
            (await session.scalars(select(User).where(User.telegram_id == telegram_id))).all()
        )
        devices = list(
            (
                await session.scalars(select(Device).where(Device.user_id == original_values[0]))
            ).all()
        )
        events = int(
            (
                await session.execute(
                    select(func.count(TelegramUpdateEvent.update_id)).where(
                        TelegramUpdateEvent.update_id.in_([update_id, update_id + 1, update_id + 2])
                    )
                )
            ).scalar_one()
        )
        assert len(users) == 1
        assert (
            users[0].id,
            users[0].trial_expires_at,
            users[0].proxy_username,
            users[0].proxy_password_ciphertext,
        ) == original_values
        assert len(devices) == 2
        assert all(device.status == "active" for device in devices)
        assert events == 3


@pytest.mark.integration
@pytest.mark.asyncio
async def test_repeated_init_rotates_both_credentials_and_active_device_is_final(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, _, settings = pairing_client
    device_id = uuid.uuid4()
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 1_000_000_000
    first = await initialize(client, device_id)
    second_response = await client.post(
        "/api/pairing/init",
        json={"device_id": str(device_id)},
    )
    assert second_response.status_code == 200
    second = second_response.json()
    assert first["pairing_session_token"] != second["pairing_session_token"]
    assert start_token(first) != start_token(second)

    old_status = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {first['pairing_session_token']}"},
    )
    crossed_status = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {start_token(second)}"},
    )
    assert old_status.status_code == crossed_status.status_code == 401

    crossed_webhook = await bind(
        client,
        settings,
        update_id=uuid.uuid4().int % 2_000_000_000,
        telegram_id=telegram_id,
        token=str(second["pairing_session_token"]),
    )
    assert crossed_webhook.status_code == 200
    still_pending = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {second['pairing_session_token']}"},
    )
    assert still_pending.status_code == 202

    paired = await bind(
        client,
        settings,
        update_id=uuid.uuid4().int % 2_000_000_000,
        telegram_id=telegram_id,
        token=start_token(second),
    )
    assert paired.status_code == 200
    final_init = await client.post("/api/pairing/init", json={"device_id": str(device_id)})
    assert final_init.status_code == 409
    assert final_init.json()["error"]["code"] == "DEVICE_ALREADY_PAIRED"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_device_limit_error_is_durable_until_new_init(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = pairing_client
    settings.device_limit_per_user = 2
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 1_000_000_000
    update_base = uuid.uuid4().int % 1_000_000_000
    pairings: list[tuple[uuid.UUID, dict[str, object]]] = []
    for index in range(3):
        device_id = uuid.uuid4()
        pairing = await initialize(client, device_id)
        pairings.append((device_id, pairing))
        response = await bind(
            client,
            settings,
            update_id=update_base + index,
            telegram_id=telegram_id,
            token=start_token(pairing),
        )
        assert response.status_code == 200

    third_id, third_pairing = pairings[-1]
    for _ in range(2):
        status = await client.get(
            "/api/pairing/status",
            params={"device_id": str(third_id)},
            headers={"Authorization": f"Bearer {third_pairing['pairing_session_token']}"},
        )
        assert status.status_code == 409
        assert status.json()["error"]["code"] == "DEVICE_LIMIT_REACHED"

    replay_init = await client.post(
        "/api/pairing/init",
        json={"device_id": str(third_id)},
    )
    assert replay_init.status_code == 200
    cleared_error_status = await client.get(
        "/api/pairing/status",
        params={"device_id": str(third_id)},
        headers={"Authorization": f"Bearer {replay_init.json()['pairing_session_token']}"},
    )
    assert cleared_error_status.status_code == 202
    async with app.state.database.sessions() as session:
        active_count = int(
            (
                await session.execute(
                    select(func.count(Device.id))
                    .join(User, User.id == Device.user_id)
                    .where(
                        User.telegram_id == telegram_id,
                        Device.status == "active",
                    )
                )
            ).scalar_one()
        )
        assert active_count == 2


@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrent_binds_cannot_exceed_device_limit(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = pairing_client
    settings.device_limit_per_user = 1
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 1_000_000_000
    first_id, second_id = uuid.uuid4(), uuid.uuid4()
    first, second = await asyncio.gather(
        initialize(client, first_id),
        initialize(client, second_id),
    )
    update_base = uuid.uuid4().int % 1_000_000_000
    responses = await asyncio.gather(
        bind(
            client,
            settings,
            update_id=update_base,
            telegram_id=telegram_id,
            token=start_token(first),
        ),
        bind(
            client,
            settings,
            update_id=update_base + 1,
            telegram_id=telegram_id,
            token=start_token(second),
        ),
    )
    assert all(response.status_code == 200 for response in responses)

    statuses = await asyncio.gather(
        client.get(
            "/api/pairing/status",
            params={"device_id": str(first_id)},
            headers={"Authorization": f"Bearer {first['pairing_session_token']}"},
        ),
        client.get(
            "/api/pairing/status",
            params={"device_id": str(second_id)},
            headers={"Authorization": f"Bearer {second['pairing_session_token']}"},
        ),
    )
    assert sorted(response.status_code for response in statuses) == [200, 409]
    async with app.state.database.sessions() as session:
        active_count = int(
            (
                await session.execute(
                    select(func.count(Device.id))
                    .join(User, User.id == Device.user_id)
                    .where(User.telegram_id == telegram_id, Device.status == "active")
                )
            ).scalar_one()
        )
        assert active_count == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pairing_rate_limit_is_shared_and_returns_retry_headers(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, _, settings = pairing_client
    settings.pairing_init_rate_per_minute = 1
    settings.pairing_init_rate_per_hour = 1
    device_id = uuid.uuid4()

    first = await client.post("/api/pairing/init", json={"device_id": str(device_id)})
    limited = await client.post("/api/pairing/init", json={"device_id": str(device_id)})

    assert first.status_code == 201
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.headers["x-ratelimit-limit"] == "1"
    assert limited.headers["x-ratelimit-remaining"] == "0"
    assert int(limited.headers["retry-after"]) >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_contract_errors_cors_expiry_and_webhook_auth(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = pairing_client
    device_id = uuid.uuid4()
    origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
    invalid_media = await client.post(
        "/api/pairing/init",
        content=b'{{"device_id":"bad"}}',
        headers={"Content-Type": "text/plain", "Origin": origin},
    )
    assert invalid_media.status_code == 415
    assert invalid_media.json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert invalid_media.headers["access-control-allow-origin"] == origin

    invalid_body = await client.post(
        "/api/pairing/init",
        json={"device_id": str(device_id), "extra": True},
    )
    assert invalid_body.status_code == 400
    assert "detail" not in invalid_body.json()

    preflight = await client.options(
        "/api/pairing/init",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-request-id",
        },
    )
    denied = await client.options(
        "/api/pairing/init",
        headers={
            "Origin": "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == origin
    assert denied.status_code == 403

    pairing = await initialize(client, device_id)
    async with app.state.database.sessions.begin() as session:
        device = (
            await session.execute(select(Device).where(Device.device_id == device_id))
        ).scalar_one()
        device.pairing_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    expired = await client.get(
        "/api/pairing/status",
        params={"device_id": str(device_id)},
        headers={"Authorization": f"Bearer {pairing['pairing_session_token']}"},
    )
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "PAIRING_EXPIRED"

    wrong_secret = await client.post(
        "/integrations/telegram/webhook/"
        + settings.telegram_webhook_path_secret.get_secret_value(),  # type: ignore[union-attr]
        headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
        json=telegram_update(1, 1, start_token(pairing)),
    )
    assert wrong_secret.status_code == 401
    assert wrong_secret.content == b""


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bot_start_and_callback_are_registered_and_queued_once(
    pairing_client: tuple[httpx.AsyncClient, object, Settings],
) -> None:
    client, app, settings = pairing_client
    telegram_id = uuid.uuid4().int % 8_000_000_000 + 60_000_000_000
    update_id = uuid.uuid4().int % 8_000_000_000 + 70_000_000_000
    path = (
        "/integrations/telegram/webhook/"
        + settings.telegram_webhook_path_secret.get_secret_value()  # type: ignore[union-attr]
    )
    headers = {
        "X-Telegram-Bot-Api-Secret-Token": (
            settings.telegram_webhook_secret.get_secret_value()  # type: ignore[union-attr]
        )
    }
    start_update = telegram_update(update_id, telegram_id, "unused", text="/start")

    first = await client.post(path, headers=headers, json=start_update)
    replay = await client.post(path, headers=headers, json=start_update)

    assert first.status_code == 200
    assert replay.status_code == 200
    async with app.state.database.sessions() as session:
        user = await session.scalar(select(User).where(User.telegram_id == telegram_id))
        assert user is not None
        assert user.trial_expires_at is None
        start_actions = (
            await session.scalars(
                select(OutboxEvent).where(
                    OutboxEvent.idempotency_key.like(f"telegram:update:{update_id}:action:%")
                )
            )
        ).all()
        assert len(start_actions) == 3

    callback_update = {
        "update_id": update_id + 1,
        "callback_query": {
            "id": f"callback-{update_id}",
            "from": {
                "id": telegram_id,
                "is_bot": False,
                "first_name": "Test",
            },
            "message": {
                "message_id": update_id,
                "date": 1_785_986_120,
                "from": {
                    "id": 999,
                    "is_bot": True,
                    "first_name": "Virgo",
                },
                "chat": {"id": telegram_id, "type": "private"},
                "text": "👤 Мой профиль",
            },
            "data": "menu:tariffs",
        },
    }
    callback = await client.post(path, headers=headers, json=callback_update)

    assert callback.status_code == 200
    async with app.state.database.sessions() as session:
        callback_actions = (
            await session.scalars(
                select(OutboxEvent).where(
                    OutboxEvent.idempotency_key.like(
                        f"telegram:update:{update_id + 1}:action:%"
                    )
                )
            )
        ).all()
        assert {event.payload_json["method"] for event in callback_actions} == {
            "answerCallbackQuery",
            "sendMessage",
        }

    pairing = await initialize(client, uuid.uuid4())
    paired = await bind(
        client,
        settings,
        update_id=update_id + 2,
        telegram_id=telegram_id,
        token=start_token(pairing),
    )

    assert paired.status_code == 200
    async with app.state.database.sessions() as session:
        user = await session.scalar(select(User).where(User.telegram_id == telegram_id))
        assert user is not None
        assert user.trial_expires_at is not None
