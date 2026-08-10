from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vpn_service.config import Settings
from vpn_service.persistence.models import NodeRuntimeMetric
from vpn_service.worker.operations_health import OperationsHealthWorker


def test_operations_health_detects_stale_and_resource_failures(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(admin_telegram_chat_ids_json=[1])
    worker = OperationsHealthWorker(None, settings)  # type: ignore[arg-type]
    now = datetime.now(UTC)
    stale = NodeRuntimeMetric(
        node_id=uuid4(),
        cpu_percent=1,
        memory_percent=1,
        disk_percent=1,
        network_rx_bytes=0,
        network_tx_bytes=0,
        gost_up=True,
        sync_agent_up=True,
        observed_at=now - timedelta(minutes=3),
    )
    unhealthy = NodeRuntimeMetric(
        node_id=uuid4(),
        cpu_percent=91,
        memory_percent=92,
        disk_percent=86,
        network_rx_bytes=0,
        network_tx_bytes=0,
        gost_up=False,
        sync_agent_up=False,
        tls_expires_at=now + timedelta(days=5),
        observed_at=now,
    )

    assert worker._problems(now, stale) == [("telemetry_stale", "180s")]
    names = {name for name, _ in worker._problems(now, unhealthy)}
    assert names == {
        "gost_down",
        "sync_agent_down",
        "cpu_critical",
        "memory_critical",
        "disk_critical",
        "tls_expiring",
    }


def test_operations_health_warns_at_70_and_marks_80_percent_critical(
    settings_factory: Callable[..., Settings],
) -> None:
    worker = OperationsHealthWorker(
        None, settings_factory(admin_telegram_chat_ids_json=[1])  # type: ignore[arg-type]
    )
    now = datetime.now(UTC)
    metric = NodeRuntimeMetric(
        node_id=uuid4(),
        cpu_percent=70,
        memory_percent=79.9,
        disk_percent=80,
        network_rx_bytes=0,
        network_tx_bytes=0,
        gost_up=True,
        sync_agent_up=True,
        observed_at=now,
    )

    problems = dict(
        worker._problems(
            now,
            metric,
            assigned_users=70,
            capacity_users=100,
            current_connections=4_000,
        )
    )

    assert problems["cpu_warning"] == "70.0%"
    assert problems["memory_warning"] == "79.9%"
    assert problems["disk_critical"] == "80.0%"
    assert problems["capacity_warning"] == "70/100 (70.0%)"
    assert problems["connections_critical"] == "4000/5000 (80.0%)"
