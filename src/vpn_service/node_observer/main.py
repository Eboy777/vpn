from __future__ import annotations

import asyncio

import uvicorn

from vpn_service.node_observer.config import NodeObserverSettings
from vpn_service.node_observer.service import NodeObserver, create_observer_app


async def run() -> None:
    settings = NodeObserverSettings()  # type: ignore[call-arg]
    observer = NodeObserver(settings)
    stop = asyncio.Event()
    app = create_observer_app(settings, observer)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=settings.node_observer_bind_host,
            port=settings.node_observer_bind_port,
            access_log=False,
            log_level="warning",
        )
    )
    reporter = asyncio.create_task(observer.run_forever(stop))
    try:
        await server.serve()
    finally:
        stop.set()
        await reporter
        await observer.close()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
