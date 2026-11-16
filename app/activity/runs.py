"""The history of what the ops service ran by itself (table ops_run), shown on the activity pages."""

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent.masking import Masker
from app.models import OpsRun

log = logging.getLogger(__name__)

# Long enough to see a quarter of runs, short enough that the table stays a few thousand rows (about 15 jobs a day).
RETENTION = timedelta(days=90)
# A report that cannot be posted is retried every minute; one failed row per hour tells the story without a flood.
FAILURE_REPEAT = timedelta(hours=1)
SUMMARY_MAX = 500


class RunLog:
    """Writes one row per run. A failing history must never break the job it describes, so nothing here raises."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession], clock: Callable[[], datetime]) -> None:
        self._sessions = sessions
        self._clock = clock

    async def record(self, name: str, kind: str, started_at: datetime, *, ok: bool, summary: str) -> None:
        try:
            async with self._sessions() as session, session.begin():
                session.add(
                    OpsRun(
                        name=name,
                        kind=kind,
                        started_at=started_at,
                        finished_at=self._clock(),
                        status="ok" if ok else "failed",
                        summary=Masker().mask(summary)[:SUMMARY_MAX],
                    )
                )
        except Exception:
            log.exception("could not record the run of %s", name)

    async def _failed_recently(self, name: str, now: datetime) -> bool:
        try:
            async with self._sessions() as session:
                row = await session.scalar(
                    select(OpsRun.id).where(
                        OpsRun.name == name, OpsRun.status == "failed", OpsRun.started_at > now - FAILURE_REPEAT
                    )
                )
            return row is not None
        except Exception:
            log.exception("could not read the history of %s", name)
            return True  # when the database is the problem, do not pile on

    def tracked(
        self, name: str, kind: str, done: str, job: Callable[[datetime], Awaitable[object]]
    ) -> Callable[[datetime], Awaitable[None]]:
        """Wrap a job that raises when it fails: record the run, then pass the exception on to the caller's retry."""

        async def run(now: datetime) -> None:
            started = self._clock()
            try:
                await job(now)
            except Exception as exc:
                if not await self._failed_recently(name, started):
                    await self.record(name, kind, started, ok=False, summary=f"{type(exc).__name__}: {exc}")
                raise
            await self.record(name, kind, started, ok=True, summary=done)

        return run

    async def prune(self, before: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(delete(OpsRun).where(OpsRun.started_at < before))
