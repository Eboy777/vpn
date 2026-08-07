from __future__ import annotations

import asyncio
import logging
import signal

from vpn_service.config import ProcessRole, Settings
from vpn_service.logging import configure_logging
from vpn_service.persistence.database import Database
from vpn_service.worker.leader import WorkerAlreadyRunningError, WorkerLeader
from vpn_service.worker.outbox import OutboxWorker

logger = logging.getLogger(__name__)


async def run() -> None:
    settings = Settings()  # type: ignore[call-arg]
    if settings.process_role is not ProcessRole.WORKER:
        raise RuntimeError("worker process requires PROCESS_ROLE=worker")
    configure_logging(settings.log_level, settings.log_format)
    database = Database(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_name, stop.set)

    try:
        async with WorkerLeader(database.engine):
            logger.info("worker_leader_acquired")
            await OutboxWorker(database.sessions, settings).run_forever(stop)
    except WorkerAlreadyRunningError:
        logger.error("worker_leader_not_acquired")
        raise
    finally:
        await database.dispose()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
