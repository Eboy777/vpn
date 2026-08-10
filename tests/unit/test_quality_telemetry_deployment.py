from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_extension_reports_quality_without_browsing_data() -> None:
    worker = (ROOT / "extension/service-worker.js").read_text()
    storage = (ROOT / "extension/src/storage.js").read_text()

    for field in ("browser_name", "browser_version", "platform", "duration_ms"):
        assert field in worker
    for event in ("connection_attempt", "node_failover", "reconnect", "tariff_viewed"):
        assert f'"{event}"' in worker
    assert "connectionAttemptStartedAt" in storage
    assert "hadSuccessfulConnection" in storage
    assert "details.url" not in worker.split("reportVpnEvent(", maxsplit=1)[1]


def test_admin_panel_exposes_quality_tables_and_funnel() -> None:
    html = (ROOT / "src/vpn_service/assets/admin/index.html").read_text()
    javascript = (ROOT / "src/vpn_service/assets/admin/admin.js").read_text()

    assert 'id="quality"' in html
    assert 'id="quality-errors"' in html
    assert 'id="shared-ips"' in html
    assert 'api("quality")' in javascript
    assert "payment_funnel" in javascript
