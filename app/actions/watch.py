"""The dead man's switch for the runners: a runner that has not polled for 3 minutes opens a P1.

Every poll is a heartbeat (`runner_heartbeat`). The runner does not poll while it runs a job, so a server with a job
in flight counts as alive (the 30 minute sweep of the jobs bounds that). Only servers whose runner has polled at least
once are watched, so a server whose runner is not installed yet raises nothing. After a restart of this service the
time counts from the restart, because nothing could poll while it was down. A server dropped from RUNNER_TOKENS is no
longer watched and its open alert is closed.
"""

from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import ActionJob, RunnerHeartbeat
from app.security.signals import Signal, Signals

SILENT_AFTER = timedelta(minutes=3)
ALERT = "RunnerSilent"


class RunnerWatch:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        hosts: set[str],
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._hosts = hosts  # a server dropped from RUNNER_TOKENS is no longer watched
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._started_at = clock()

    async def check(self) -> None:
        now = self._clock()
        async with self._sessions() as session:
            beats = (await session.scalars(select(RunnerHeartbeat))).all()
            working = set(
                await session.scalars(select(ActionJob.host).where(ActionJob.status.in_(("delivered", "running"))))
            )
        for beat in beats:
            if beat.host not in self._hosts:  # dropped from RUNNER_TOKENS: close what was open, raise nothing new
                await self._signals.set(ALERT, "P1", {"host": beat.host}, None)
                continue
            quiet = timedelta(0) if beat.host in working else now - max(beat.last_seen_at, self._started_at)
            scope = {"host": beat.host}
            minutes = int(quiet.total_seconds() // 60)
            summary = self._locale.t("actions.runner_silent", host=beat.host, minutes=minutes)
            silent = Signal(labels=scope, summary=summary) if quiet > SILENT_AFTER else None
            await self._signals.set(ALERT, "P1", scope, silent)
