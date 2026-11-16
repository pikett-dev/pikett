import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, time, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.activity.runs import RETENTION as RUN_RETENTION
from app.activity.runs import RunLog
from app.i18n import Locale
from app.security import hostreports, overview
from app.security.base import Check, ReportKind, Scheduled, Section
from app.security.hostreports import HostReportIn
from app.security.signals import Signal, Signals

log = logging.getLogger(__name__)

REPORT_MISSING = "HostReportMissing"
REPORT_INVALID = "HostReportInvalid"
JOB_FAILED = "ScheduledJobFailed"
# Lynis runs weekly; a year of rows keeps the score trend, everything else needs only the newest rows.
RETENTION = timedelta(days=400)


class SecurityService:
    """Takes host reports in, hands them to the checks, and notices reports that stop arriving."""

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        checks: list[Check],
        *,
        daily: list[Section] | None = None,
        weekly: list[Section] | None = None,
        locale: Locale,
    ) -> None:
        """`daily` and `weekly` order the reports; without them each report lists all checks without headings."""
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._runs = RunLog(sessions, clock)
        self._checks = checks
        self._daily = daily or [Section("", tuple(checks))]
        self._weekly = weekly or [Section("", tuple(checks))]
        self._by_kind: dict[str, list[Check]] = defaultdict(list)
        for check in checks:
            for kind in check.report_kinds():
                self._by_kind[kind.name].append(check)
        # Like the watchdog: a report that never arrived counts from the start of this process.
        self._started = clock()

    def knows(self, kind: str) -> bool:
        return kind in self._by_kind

    async def ingest(self, report: HostReportIn) -> None:
        """Store the report, then let its checks evaluate it. A failing check does not lose the report."""
        async with self._sessions() as session, session.begin():
            row = await hostreports.store(session, report, self._clock())
        scope = {"host": row.host, "kind": row.kind}
        failed: list[str] = []
        for check in self._by_kind[report.kind]:
            try:
                await check.on_report(row)
            except Exception as exc:  # the data is the collector's, so a check can trip over it
                log.exception("check %s failed on the %s report of %s", type(check).__name__, row.kind, row.host)
                failed.append(f"{type(check).__name__}: {type(exc).__name__}: {exc}"[:300])
        signal = None
        if failed:
            summary = self._locale.t("security.service.invalid", kind=row.kind, host=row.host, failed="; ".join(failed))
            signal = Signal(labels=scope, summary=summary)
        await self._signals.set(REPORT_INVALID, "P2", scope, signal)

    def _expected(self) -> list[ReportKind]:
        return [kind for check in self._checks for kind in check.report_kinds()]

    async def check_freshness(self) -> None:
        """Open a P2 for every expected report that is overdue, and resolve it once the report is back."""
        now = self._clock()
        expected = self._expected()
        async with self._sessions() as session:
            newest = {name: await hostreports.latest(session, name) for name in {kind.name for kind in expected}}
        firing: list[Signal] = []
        for kind in expected:
            for host in kind.hosts:
                row = newest[kind.name].get(host)
                seen = row.received_at if row else None
                if now - (seen or self._started) <= kind.max_age:
                    continue
                since = (
                    self._locale.t("security.service.since", at=self._locale.day_time(seen))
                    if seen
                    else self._locale.t("security.common.never")
                )
                firing.append(
                    Signal(
                        labels={"host": host, "kind": kind.name},
                        summary=self._locale.t("security.service.missing", kind=kind.name, host=host, since=since),
                    )
                )
        await self._signals.reconcile(REPORT_MISSING, "P2", {}, firing)

    async def periodic(self) -> None:
        """Every few minutes: overdue reports, then each check's own periodic verdicts."""
        await self.check_freshness()
        now = self._clock()
        for check in self._checks:
            try:
                await check.periodic(now)
            except Exception:
                log.exception("the periodic step of check %s failed", type(check).__name__)

    def scheduled(self) -> list[Scheduled]:
        """The checks' jobs, each guarded: a failure becomes a P2 and the day counts as done, so a broken job does
        not download feeds or clone repositories every minute until midnight."""
        jobs = [job for check in self._checks for job in check.scheduled()]
        jobs.append(Scheduled("host_report_prune", time(5, 0), self._prune))
        return [Scheduled(job.name, job.at, self._guarded(job), job.weekday) for job in jobs]

    def _guarded(self, job: Scheduled) -> Callable[[datetime], Awaitable[None]]:
        async def run(now: datetime) -> None:
            scope = {"job": job.name}
            started = self._clock()
            try:
                await job.run(now)
            except Exception as exc:
                log.exception("scheduled job %s failed", job.name)
                error = f"{type(exc).__name__}: {exc}"
                summary = self._locale.t("security.service.job_failed", job=job.name, error=error)
                await self._signals.set(JOB_FAILED, "P2", scope, Signal(labels=scope, summary=summary[:500]))
                await self._runs.record(job.name, "check", started, ok=False, summary=f"{type(exc).__name__}: {exc}")
                return
            await self._signals.set(JOB_FAILED, "P2", scope, None)
            await self._runs.record(
                job.name, "check", started, ok=True, summary=self._locale.t("security.service.run_done")
            )

        return run

    async def _prune(self, now: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await hostreports.prune(session, now - RETENTION)
        await self._runs.prune(now - RUN_RETENTION)

    async def overview(self) -> list[overview.CheckRow]:
        """For the ops overview page: per check its last run, whether it is overdue, and its newest result."""
        return await overview.build(self._locale, self._sessions, self._clock(), self._checks, self._started)

    async def daily_lines(self, now: datetime) -> list[str]:
        return await self._report(self._daily, "daily_lines", now)

    async def weekly_lines(self, now: datetime) -> list[str]:
        return await self._report(self._weekly, "weekly_lines", now)

    async def _report(self, sections: list[Section], method: str, now: datetime) -> list[str]:
        """The lines of each section under its heading; a section without any line is left out."""
        lines: list[str] = []
        for section in sections:
            part: list[str] = []
            for check in section.checks:
                try:
                    part += await getattr(check, method)(now)
                except Exception:
                    log.exception("check %s failed to write its report lines", type(check).__name__)
                    part.append(self._locale.t("security.service.part_missing", check=type(check).__name__))
            if part:
                lines += [f"_{section.title}_", *part] if section.title else part
        return lines
