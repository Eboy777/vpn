from __future__ import annotations

import asyncio
import signal

from vpn_service.canary_agent.agent import CanaryAgent
from vpn_service.canary_agent.config import CanaryAgentSettings


async def run() -> None:
    settings = CanaryAgentSettings()  # type: ignore[call-arg]
    agent = CanaryAgent(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_name, stop.set)
    try:
        await agent.run_forever(stop)
    finally:
        await agent.close()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
