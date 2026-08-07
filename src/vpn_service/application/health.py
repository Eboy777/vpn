from __future__ import annotations

from collections.abc import Awaitable, Callable

DatabaseProbe = Callable[[], Awaitable[bool]]


async def check_database(probe: DatabaseProbe) -> bool:
    try:
        return await probe()
    except Exception:
        return False
