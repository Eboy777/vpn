from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from vpn_service.application.admin_dashboard import _percentile
from vpn_service.http.schemas import DeviceTelemetryRequest


def _payload(event_type: str, **values: object) -> dict[str, object]:
    return {
        "event_id": uuid.uuid4(),
        "event_type": event_type,
        "session_id": uuid.uuid4(),
        "extension_version": "1.2.3",
        "browser_name": "Chromium",
        "browser_version": "140.0",
        "platform": "mac",
        **values,
    }


def test_device_telemetry_accepts_timed_connection_and_private_funnel_event() -> None:
    connected = DeviceTelemetryRequest.model_validate(
        _payload("vpn_started", duration_ms=1250)
    )
    tariff = DeviceTelemetryRequest.model_validate(
        {
            **_payload("tariff_viewed"),
            "session_id": None,
        }
    )

    assert connected.duration_ms == 1250
    assert tariff.session_id is None


def test_device_telemetry_requires_session_and_restricts_duration() -> None:
    with pytest.raises(ValidationError, match="session_id is required"):
        DeviceTelemetryRequest.model_validate(
            {**_payload("vpn_started"), "session_id": None}
        )
    with pytest.raises(ValidationError, match="duration_ms is allowed"):
        DeviceTelemetryRequest.model_validate(_payload("vpn_heartbeat", duration_ms=1))


def test_nearest_rank_percentiles_are_stable_for_small_samples() -> None:
    assert _percentile([], 0.95) is None
    assert _percentile([100, 200, 300, 400, 500], 0.95) == 500
    assert _percentile([500, 100, 300, 200, 400], 0.5) == 300
