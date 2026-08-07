from __future__ import annotations

import asyncio
import logging
import signal

from vpn_service.logging import configure_logging
from vpn_service.node_agent.agent import NodeSyncAgent
from vpn_service.node_agent.config import NodeAgentSettings


async def run() -> None:
    settings = NodeAgentSettings()  # type: ignore[call-arg]
    configure_logging("INFO", "json")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_name, stop.set)
    agent = NodeSyncAgent(settings)
    try:
        await agent.run_forever(stop)
    finally:
        await agent.close()


def main() -> None:
    try:
        asyncio.run(run())
    except Exception:
        logging.getLogger(__name__).exception("node_agent_stopped")
        raise


if __name__ == "__main__":
    main()
