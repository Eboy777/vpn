from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from vpn_service.config import Settings
from vpn_service.persistence.models import Node
from vpn_service.worker.node_snapshot_watchdog import _advance_snapshot_health


def _node(now: datetime) -> Node:
    return Node(
        id=uuid.uuid4(),
        name=f"node-{uuid.uuid4()}",
        host="node.example.test",
        port=443,
        country_code="NL",
        provider="test",
        status="active",
        capacity_users=100,
        credentials_revision="b" * 64,
        applied_credentials_revision="a" * 64,
        applied_snapshot_valid_until=now + timedelta(minutes=5),
        snapshot_ack_deadline=now - timedelta(seconds=1),
        snapshot_ack_failures=0,
        last_sync_at=now,
    )


def test_third_missed_ack_window_blocks_node(
    settings_factory: Callable[..., Settings],
) -> None:
    now = datetime(2026, 8, 8, 12, tzinfo=UTC)
    settings = settings_factory()
    node = _node(now)

    for expected_failures in (1, 2):
        missed, blocked = _advance_snapshot_health(node, now=now, settings=settings)
        assert missed is True
        assert blocked is False
        assert node.snapshot_ack_failures == expected_failures
        node.snapshot_ack_deadline = now - timedelta(seconds=1)

    missed, blocked = _advance_snapshot_health(node, now=now, settings=settings)
    assert missed is True
    assert blocked is True
    assert node.snapshot_ack_failures == 3


def test_stale_heartbeat_blocks_even_without_pending_revision(
    settings_factory: Callable[..., Settings],
) -> None:
    now = datetime(2026, 8, 8, 12, tzinfo=UTC)
    settings = settings_factory()
    node = _node(now)
    node.applied_credentials_revision = node.credentials_revision
    node.snapshot_ack_deadline = None
    node.last_sync_at = now - timedelta(
        seconds=settings.node_snapshot_heartbeat_timeout_seconds + 1
    )

    missed, blocked = _advance_snapshot_health(node, now=now, settings=settings)

    assert missed is False
    assert blocked is True
