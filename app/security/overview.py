"""What each security check last did and what it found, for the ops overview page.

The freshness comes from the places the checks already write to: the host reports of the collectors, the run history
of the scheduled jobs (ops_run) and the saved backup state. The result sentences are the lines the checks put in the
daily and weekly reports, so the page and Slack never disagree.
"""

import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import HostReport, OpsRun
from app.security import hostreports
from app.security.backup import STATE as BACKUP_STATE
from app.security.base import Check
from app.security.lines import needs_action
from app.security.names import CHECK_KEYS, GROUP_OF, OTHER_GROUP
from app.security.state import load_state

log = logging.getLogger(__name__)

DAILY = timedelta(hours=26)  # a daily job or report, with two hours of slack
WEEKLY = timedelta(days=8)
BACKUP_MAX_AGE = timedelta(hours=2)  # the backup check runs every 30 minutes; its own digest line warns after 2 h

STRIP_DAYS = 14
STRIP_OK, STRIP_FAILED, STRIP_PARTIAL, STRIP_NONE = "ok", "failed", "partial", "none"

OK, NEW, WARN, PROBLEM, OVERDUE = "ok", "new", "warn", "problem", "overdue"
_SEVERITY = {OK: 0, NEW: 1, WARN: 2, OVERDUE: 3, PROBLEM: 4}
_SLACK_EMOJI = re.compile(r":[a-z0-9_+-]+:\s*")


@dataclass(frozen=True)
class CheckRow:
    label: str
    state: str  # one of OK, NEW, WARN, PROBLEM, OVERDUE
    last_run: datetime | None
    cadence: str
    lines: list[str]
    jobs: list[str]  # names in ops_run, for the link to the history
    group: str = ""
    strip: tuple[tuple[date, str], ...] = ()  # one state per day, oldest first
    name: str = ""  # the check's class name, the key of its help text

    @property
    def headline(self) -> str:
        return self.lines[0] if self.lines else ""

    @property
    def rest(self) -> list[str]:
        return [line.removeprefix("• ") for line in self.lines[1:]]


def plain(line: str) -> str:
    """A report line is Slack markup (`:warning:`, `*bold*`); the page shows it as text."""
    return _SLACK_EMOJI.sub("", line).replace("*", "").strip()


def _worse(a: str, b: str) -> str:
    return a if _SEVERITY[a] >= _SEVERITY[b] else b


def _line_state(lines: list[str]) -> str:
    if any(":red_circle:" in line for line in lines):  # the patch line carries "Health rot" after other text
        return PROBLEM
    # A line needs a person when it says so (`Line.needs_action`: a pending reboot, a newer image) or warns.
    if any(line.startswith(":warning:") or needs_action(line) for line in lines):
        return WARN
    return OK


async def _lines(locale: Locale, check: Check, now: datetime) -> list[str]:
    found: list[str] = []
    for method in (check.daily_lines, check.weekly_lines):
        try:
            found += [line for line in await method(now) if line not in found]
        except Exception:
            log.exception("check %s failed to write its overview lines", type(check).__name__)
            return [locale.t("web.overview.unreadable")]
    return found


async def _cadence_and_state(
    locale: Locale, session: AsyncSession, check: Check, now: datetime, started: datetime
) -> tuple[str, str, datetime | None, list[str]]:
    """How often the check runs, how fresh its newest run is, and extra lines for a failed run."""
    seen: list[datetime] = []
    cadence: list[str] = []
    state = OK
    extra: list[str] = []

    def judge(last: datetime | None, max_age: timedelta) -> None:
        nonlocal state
        if last is not None:
            seen.append(last)
        if (last is None and now - started <= max_age) or (last is not None and now - last <= max_age):
            state = _worse(state, NEW if last is None else OK)
        else:
            state = _worse(state, OVERDUE)

    for kind in check.report_kinds():
        newest = await hostreports.latest(session, kind.name)
        cadence.append(locale.t("web.cadence.report", hosts=", ".join(kind.hosts)))
        for host in kind.hosts:
            row = newest.get(host)
            judge(row.received_at if row else None, kind.max_age)
    for job in check.scheduled():
        run = await session.scalar(select(OpsRun).where(OpsRun.name == job.name).order_by(OpsRun.started_at.desc()))
        when = f"{job.at:%H:%M}"
        cadence.append(locale.t("web.cadence.weekly" if job.weekday is not None else "web.cadence.daily", at=when))
        judge(run.started_at if run else None, WEEKLY if job.weekday is not None else DAILY)
        if run is not None and run.status == "failed":
            state = _worse(state, PROBLEM)
            extra.append(locale.t("web.overview.last_run_failed", summary=run.summary))
    saved = await load_state(session, BACKUP_STATE) if type(check).__name__ == "BackupCheck" else None
    if saved is not None:
        cadence.append(locale.t("web.cadence.half_hourly"))
        judge(saved.updated_at, BACKUP_MAX_AGE)
    return ", ".join(cadence) or locale.t("web.cadence.events"), state, max(seen) if seen else None, extra


def _day(moment: datetime, tz: ZoneInfo) -> date:
    return moment.astimezone(tz).date()


async def _strip(session: AsyncSession, check: Check, now: datetime, tz: ZoneInfo) -> tuple[tuple[date, str], ...]:
    """The last days of a check that runs every day: whether its reports arrived and its jobs ran without error.

    A weekly check has no strip: most of its cells would be empty by design.
    """
    kinds = check.report_kinds()
    jobs = check.scheduled()
    if not kinds and not jobs:
        return ()
    if any(job.weekday is not None for job in jobs) or any(kind.max_age >= WEEKLY for kind in kinds):
        return ()
    today = _day(now, tz)
    days = [today - timedelta(days=offset) for offset in range(STRIP_DAYS - 1, -1, -1)]
    since = datetime.combine(days[0], time.min, tzinfo=tz)
    parts: dict[date, list[str]] = {day: [] for day in days}
    if jobs:
        names = [job.name for job in jobs]
        rows = await session.execute(
            select(OpsRun.started_at, OpsRun.status).where(OpsRun.name.in_(names), OpsRun.started_at >= since)
        )
        seen: dict[date, set[str]] = {}
        for started_at, status in rows:
            seen.setdefault(_day(started_at, tz), set()).add(status)
        for day in days:
            got = seen.get(day, set())
            parts[day].append(STRIP_FAILED if "failed" in got else STRIP_OK if got else STRIP_NONE)
    if kinds:
        expected = {(kind.name, host) for kind in kinds for host in kind.hosts}
        report_rows = await session.execute(
            select(HostReport.kind, HostReport.host, HostReport.received_at).where(
                HostReport.kind.in_([kind.name for kind in kinds]), HostReport.received_at >= since
            )
        )
        arrived: dict[date, set[tuple[str, str]]] = {}
        for kind_name, host, received_at in report_rows:
            arrived.setdefault(_day(received_at, tz), set()).add((kind_name, host))
        for day in days:
            got_reports = len(arrived.get(day, set()) & expected)
            parts[day].append(
                STRIP_OK if got_reports == len(expected) else STRIP_NONE if got_reports == 0 else STRIP_PARTIAL
            )
    result = []
    for day in days:
        states = parts[day]
        if STRIP_FAILED in states:
            result.append((day, STRIP_FAILED))
        elif all(state == STRIP_NONE for state in states):
            result.append((day, STRIP_NONE))
        elif all(state == STRIP_OK for state in states):
            result.append((day, STRIP_OK))
        else:
            result.append((day, STRIP_PARTIAL))
    return tuple(result)


async def build(
    locale: Locale,
    sessions: async_sessionmaker[AsyncSession],
    now: datetime,
    checks: list[Check],
    started: datetime,
) -> list[CheckRow]:
    rows: list[CheckRow] = []
    for check in checks:
        name = type(check).__name__
        lines = await _lines(locale, check, now)
        async with sessions() as session:
            cadence, state, last, extra = await _cadence_and_state(locale, session, check, now, started)
            strip = await _strip(session, check, now, locale.tz)
        lines = extra + lines
        rows.append(
            CheckRow(
                label=locale.t(f"security.{CHECK_KEYS[name]}.label") if name in CHECK_KEYS else name,
                state=_worse(state, _line_state(lines)),
                last_run=last,
                cadence=cadence,
                lines=[plain(line) for line in lines],
                jobs=[job.name for job in check.scheduled()],
                group=GROUP_OF.get(name, OTHER_GROUP),
                strip=strip,
                name=name,
            )
        )
    return rows
