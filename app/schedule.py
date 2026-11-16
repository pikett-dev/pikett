from collections.abc import Awaitable, Callable
from datetime import datetime, time
from zoneinfo import ZoneInfo

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import last_run, mark_run


async def run_if_due(
    sessions: async_sessionmaker[AsyncSession],
    name: str,
    now: datetime,
    at: time,
    run: Callable[[datetime], Awaitable[object]],
    *,
    tz: ZoneInfo,
    weekday: int | None = None,
) -> bool:
    """Run `run` once per day in `tz` after `at` (only on `weekday` if given, Monday = 0).

    A restart later in the day catches up. The day counts as done only when `run` returns; if it raises, the next
    check (a minute later) tries again.
    """
    local = now.astimezone(tz)
    if local.time() < at or (weekday is not None and local.weekday() != weekday):
        return False
    async with sessions() as session:
        last = await last_run(session, name)
    if last is not None and last.astimezone(tz).date() == local.date():
        return False
    await run(now)
    async with sessions() as session, session.begin():
        await mark_run(session, name, now)
    return True
