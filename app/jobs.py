import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, time
from typing import Protocol

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.actions.service import ActionService
from app.actions.watch import RunnerWatch
from app.activity.runs import RunLog
from app.agent.service import AnalysisService
from app.i18n import Locale
from app.incidents.digest import build_digest
from app.incidents.review import review_lines
from app.incidents.service import IncidentService
from app.notify.base import ChatNotifier
from app.schedule import run_if_due
from app.security.service import SecurityService

log = logging.getLogger(__name__)


class Tick(Protocol):
    async def tick(self) -> None: ...


TICK_SECONDS = 30
HEARTBEAT_SECONDS = 300
SCHEDULE_CHECK_SECONDS = 60
SECURITY_SECONDS = 300  # missing reports, exploited vulnerabilities
DIGEST_TIME = time(8, 0)
WEEKLY_WEEKDAY = 0  # Monday, with the daily digest


class Jobs:
    """Background loops: retries/reminders, the dead man's switch ping, the reports and the security jobs."""

    def __init__(
        self,
        service: IncidentService,
        chat: ChatNotifier,
        sessions: async_sessionmaker[AsyncSession],
        clock: Callable[[], datetime],
        base_url: str,
        ping_url: str | None,
        client: httpx.AsyncClient,
        *,
        locale: Locale,
        analysis: AnalysisService | None = None,
        security: SecurityService | None = None,
        actions: ActionService | None = None,
        runner_watch: RunnerWatch | None = None,
        action_steps: tuple[Tick, ...] = (),
    ) -> None:
        self._locale = locale
        self._service = service
        self._chat = chat
        self._sessions = sessions
        self._clock = clock
        self._base_url = base_url
        self._ping_url = ping_url
        self._client = client
        self._analysis = analysis
        self._security = security
        self._actions = actions
        self._runner_watch = runner_watch
        self._action_steps = action_steps
        self._runs = RunLog(sessions, clock)
        self._tasks: list[asyncio.Task[None]] = []

    def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self._loop("tick", TICK_SECONDS, self.tick)),
            asyncio.create_task(self._loop("schedule", SCHEDULE_CHECK_SECONDS, self.run_scheduled)),
        ]
        if self._ping_url:
            self._tasks.append(asyncio.create_task(self._loop("heartbeat", HEARTBEAT_SECONDS, self.ping)))
        if self._security is not None:
            periodic = self._security.periodic
            self._tasks.append(asyncio.create_task(self._loop("security", SECURITY_SECONDS, periodic)))

    async def tick(self) -> None:
        """One round of retries and reminders. An analysis step that fails must not hold back the incident steps."""
        await self._service.tick()
        if self._analysis is not None:
            try:
                await self._analysis.tick()
            except Exception:
                log.exception("the analysis tick failed")
        if self._actions is not None:
            try:
                await self._actions.expire()
            except Exception:
                log.exception("expiring the jobs failed")
        if self._runner_watch is not None:
            try:
                await self._runner_watch.check()
            except Exception:
                log.exception("the runner watch failed")
        for step in self._action_steps:
            try:
                await step.tick()
            except Exception:
                log.exception("the action step %s failed", type(step).__name__)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    @staticmethod
    async def _loop(name: str, interval: float, job: Callable[[], Awaitable[object]]) -> None:
        while True:
            try:
                await job()
            except Exception:
                log.exception("job %s failed", name)
            await asyncio.sleep(interval)

    async def ping(self) -> None:
        """healthchecks.io alerts through its own channels when these pings stop."""
        if not self._ping_url:
            return
        try:
            response = await self._client.get(self._ping_url, timeout=10)
            response.raise_for_status()
        except httpx.HTTPError as error:
            # The ping URL carries the token of the monitor, and httpx puts the URL into its messages (and the
            # location of a redirect). Say what failed without it; `from None` keeps the original out of the traceback.
            status = error.response.status_code if isinstance(error, httpx.HTTPStatusError) else None
            raise RuntimeError(f"the heartbeat ping failed ({status or type(error).__name__})") from None

    async def run_scheduled(self) -> None:
        """The daily digest, the weekly report and the security jobs, each once per day when due."""
        now = self._clock()
        try:  # a digest that cannot be posted (Slack down) is retried a minute later, but holds up nothing else
            await self.run_digest_if_due()
        except Exception:
            log.exception("posting the digest failed")
        try:
            weekly = self._runs.tracked("weekly", "report", self._locale.t("jobs.weekly_posted"), self._post_weekly)
            await run_if_due(
                self._sessions, "weekly", now, DIGEST_TIME, weekly, tz=self._locale.tz, weekday=WEEKLY_WEEKDAY
            )
        except Exception:
            log.exception("posting the weekly report failed")
        if self._security is None:
            return
        for job in self._security.scheduled():
            try:
                await run_if_due(
                    self._sessions, job.name, now, job.at, job.run, tz=self._locale.tz, weekday=job.weekday
                )
            except Exception:
                log.exception("scheduled job %s failed", job.name)

    async def run_digest_if_due(self) -> bool:
        """Post the digest once per day after 08:00 local time; a restart later in the day catches up."""
        post = self._runs.tracked("digest", "report", self._locale.t("jobs.digest_posted"), self._post_digest)
        return await run_if_due(self._sessions, "digest", self._clock(), DIGEST_TIME, post, tz=self._locale.tz)

    async def _post_digest(self, now: datetime) -> None:
        text = await build_digest(self._locale, self._sessions, now, self._base_url)
        if self._security is not None and (lines := await self._security.daily_lines(now)):
            text += "\n" + self._locale.t("jobs.security_heading") + "\n" + "\n".join(lines)
        await self._chat.post_ops(text)

    async def _post_weekly(self, now: datetime) -> None:
        try:  # a failing review must not hold back the security part of the report
            review = await review_lines(self._locale, self._sessions, now)
        except Exception:
            log.exception("could not build the alarm review")
            review = [self._locale.t("jobs.review_failed")]
        lines = [self._locale.t("jobs.weekly_title"), self._locale.t("jobs.weekly_alarms"), *review]
        if self._security is not None and (security := await self._security.weekly_lines(now)):
            lines += [self._locale.t("jobs.security_heading"), *security]
        await self._chat.post_ops("\n".join(lines))
