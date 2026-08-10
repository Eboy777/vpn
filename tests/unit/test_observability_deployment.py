from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OBSERVABILITY = ROOT / "deploy/observability"


def test_observability_stack_keeps_dashboards_private_and_pins_images() -> None:
    compose = (OBSERVABILITY / "docker-compose.observability.yml").read_text()

    assert "127.0.0.1}:3000:3000" in compose
    assert "CONTROL_WIREGUARD_IP" in compose
    assert "./secrets/metrics_token:/run/secrets/metrics_token:ro" in compose
    assert "vpn-control_private" in compose
    assert ":latest" not in compose
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in compose


def test_prometheus_and_loki_configs_have_auth_and_retention_boundaries() -> None:
    prometheus = (OBSERVABILITY / "prometheus.yml").read_text()
    loki = (OBSERVABILITY / "loki.yml").read_text()
    ignore = (ROOT / ".gitignore").read_text()

    assert "bearer_token_file: /run/secrets/metrics_token" in prometheus
    assert 'targets: ["api:8000"]' in prometheus
    assert "retention_period: 720h" in loki
    assert "auth_enabled: false" in loki
    assert "deploy/observability/secrets/" in ignore


def test_remote_node_logs_use_environment_credentials_and_valid_dashboard_json() -> None:
    node_alloy = (OBSERVABILITY / "node.alloy.example").read_text()
    dashboard = json.loads((OBSERVABILITY / "grafana/dashboards/virgo-overview.json").read_text())

    assert 'password = sys.env("LOKI_PASSWORD")' in node_alloy
    assert 'url = sys.env("LOKI_PUSH_URL")' in node_alloy
    assert "replace-with" not in node_alloy
    assert dashboard["uid"] == "virgo-overview"
    assert {panel["type"] for panel in dashboard["panels"]} >= {"stat", "timeseries", "logs"}
    titles = {panel["title"] for panel in dashboard["panels"]}
    assert "Успешность и время подключения" in titles
    assert "Заполненность и прогноз нод" in titles
    assert "Скорость по странам и провайдерам" in titles
