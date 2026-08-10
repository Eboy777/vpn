from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest

from vpn_service.canary_agent.agent import CanaryAgent
from vpn_service.canary_agent.config import CanaryAgentSettings


@pytest.mark.asyncio
async def test_canary_retries_same_run_after_control_response_is_lost() -> None:
    reports: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reports.append(json.loads(request.content))
        if len(reports) == 1:
            return httpx.Response(503, json={"error": {"code": "TEMPORARY"}})
        return httpx.Response(200, json={"processed": False, "outcomes": []})

    settings = CanaryAgentSettings(
        control_api_base_url="https://api-a.example.test",
        canary_id=uuid.uuid4(),
        canary_token="C" * 43,
        canary_nodes_json=[
            {
                "node_id": str(uuid.uuid4()),
                "host": "node.example.test",
                "port": 443,
                "username": "u_abcdefghijklmnopqrstuvwxyz",
                "password": "P" * 32,
            }
        ],
        canary_probe_urls_json=[
            "https://probe-a.example.test/health",
            "https://probe-b.example.test/health",
        ],
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    agent = CanaryAgent(settings, control_client=client)
    node_result = {
        "check_id": str(uuid.uuid4()),
        "node_id": str(settings.canary_nodes_json[0].node_id),
        "targets": [
            {
                "target": "probe-a.example.test",
                "success": True,
                "latency_ms": 10,
                "status_code": 204,
                "error_code": None,
            },
            {
                "target": "probe-b.example.test",
                "success": True,
                "latency_ms": 12,
                "status_code": 204,
                "error_code": None,
            },
        ],
    }
    check_node = AsyncMock(return_value=node_result)
    agent._check_node = check_node  # type: ignore[method-assign]
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await agent.check_once()
        result = await agent.check_once()
    finally:
        await client.aclose()

    assert result["processed"] is False
    assert reports[0]["run_id"] == reports[1]["run_id"]
    assert reports[0]["nodes"] == reports[1]["nodes"]
    assert check_node.await_count == 1
