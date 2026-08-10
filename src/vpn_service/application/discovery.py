from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vpn_service.config import Settings
from vpn_service.domain.errors import ApplicationError
from vpn_service.persistence.models import CanaryRun, ControlIngress
from vpn_service.security.discovery_signing import sign_discovery_document

_MAX_DISCOVERY_URLS = 20


class DiscoveryService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._settings = settings

    async def signed_document(self) -> dict[str, object]:
        private_key = self._settings.discovery_signing_private_key
        if private_key is None:
            raise ApplicationError(
                503,
                "DISCOVERY_NOT_CONFIGURED",
                "Control ingress discovery is not configured",
            )
        async with self._sessions() as session:
            now = await _database_now(session)
            urls = await self._active_urls(session)
        generated_at = _format(now)
        expires_at = _format(now + timedelta(seconds=self._settings.discovery_document_ttl_seconds))
        version = hashlib.sha256("\n".join(urls).encode()).hexdigest()
        payload: dict[str, object] = {
            "version": version,
            "generated_at": generated_at,
            "expires_at": expires_at,
            "control_urls": urls,
            "key_id": self._settings.discovery_signing_key_id,
        }
        payload["signature"] = sign_discovery_document(
            payload,
            private_key.get_secret_value(),
        )
        return payload

    async def active_urls(self) -> list[str]:
        async with self._sessions() as session:
            return await self._active_urls(session)

    async def list_admin(self) -> dict[str, object]:
        async with self._sessions() as session:
            managed = list(
                (
                    await session.scalars(
                        select(ControlIngress).order_by(
                            ControlIngress.priority,
                            ControlIngress.created_at,
                        )
                    )
                ).all()
            )
            latest_run = await session.scalar(
                select(CanaryRun).order_by(CanaryRun.checked_at.desc()).limit(1)
            )
        health = {
            item.get("url"): item
            for item in (latest_run.response_json.get("ingresses", []) if latest_run else [])
        }
        bootstrap = _bootstrap_urls(self._settings)
        return {
            "ingresses": [
                {
                    "id": None,
                    "url": url,
                    "priority": index + 1,
                    "enabled": True,
                    "bootstrap": True,
                    "health": health.get(url),
                }
                for index, url in enumerate(bootstrap)
            ]
            + [
                {
                    "id": str(item.id),
                    "url": item.url,
                    "priority": item.priority,
                    "enabled": item.enabled,
                    "bootstrap": False,
                    "health": health.get(item.url),
                }
                for item in managed
            ],
            "signing_configured": self._settings.discovery_signing_private_key is not None,
        }

    async def add(self, *, url: str, priority: int) -> dict[str, object]:
        normalized = normalize_https_origin(url)
        if normalized in _bootstrap_urls(self._settings):
            raise ApplicationError(409, "INGRESS_EXISTS", "Control ingress already exists")
        async with self._sessions.begin() as session:
            existing = await session.scalar(
                select(ControlIngress.id).where(ControlIngress.url == normalized)
            )
            if existing is not None:
                raise ApplicationError(409, "INGRESS_EXISTS", "Control ingress already exists")
            count = int(await session.scalar(select(func.count(ControlIngress.id))) or 0)
            if count + len(_bootstrap_urls(self._settings)) >= _MAX_DISCOVERY_URLS:
                raise ApplicationError(409, "INGRESS_LIMIT", "Control ingress limit reached")
            item = ControlIngress(
                id=uuid.uuid4(),
                url=normalized,
                priority=priority,
                enabled=True,
            )
            session.add(item)
        return {
            "id": str(item.id),
            "url": item.url,
            "priority": item.priority,
            "enabled": item.enabled,
        }

    async def update(
        self,
        ingress_id: uuid.UUID,
        *,
        enabled: bool,
        priority: int,
    ) -> dict[str, object]:
        async with self._sessions.begin() as session:
            item = await session.get(ControlIngress, ingress_id, with_for_update=True)
            if item is None:
                raise ApplicationError(404, "INGRESS_NOT_FOUND", "Control ingress was not found")
            item.enabled = enabled
            item.priority = priority
            item.updated_at = await _database_now(session)
        return {
            "id": str(item.id),
            "url": item.url,
            "priority": item.priority,
            "enabled": item.enabled,
        }

    async def delete(self, ingress_id: uuid.UUID) -> dict[str, object]:
        async with self._sessions.begin() as session:
            item = await session.get(ControlIngress, ingress_id, with_for_update=True)
            if item is None:
                raise ApplicationError(404, "INGRESS_NOT_FOUND", "Control ingress was not found")
            await session.delete(item)
        return {"deleted": True, "id": str(ingress_id)}

    async def _active_urls(self, session: AsyncSession) -> list[str]:
        managed = list(
            (
                await session.scalars(
                    select(ControlIngress.url)
                    .where(ControlIngress.enabled.is_(True))
                    .order_by(ControlIngress.priority, ControlIngress.created_at)
                )
            ).all()
        )
        return list(dict.fromkeys([*_bootstrap_urls(self._settings), *managed]))[
            :_MAX_DISCOVERY_URLS
        ]

    async def active_urls_in_session(self, session: AsyncSession) -> list[str]:
        return await self._active_urls(session)


def normalize_https_origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("control ingress must be a plain HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port not in {None, 443}
    ):
        raise ValueError("control ingress must be a plain HTTPS origin")
    host = parsed.hostname.rstrip(".").lower()
    return f"https://{host}"


def _bootstrap_urls(settings: Settings) -> list[str]:
    return [str(url).rstrip("/") for url in settings.public_control_urls_json]


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(select(func.now()))
    assert value is not None
    return value.astimezone(UTC)


def _format(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
