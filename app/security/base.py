"""What a security check plugs into: the reports it reads, the jobs it runs, and its lines in the reports."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Protocol

from app.models import HostReport


@dataclass(frozen=True)
class ReportKind:
    """A report kind a check expects from these hosts, at least every `max_age`."""

    name: str
    hosts: tuple[str, ...]
    max_age: timedelta


@dataclass(frozen=True)
class Scheduled:
    """A job that runs once a day (or once a week on `weekday`, Monday = 0) after `at` in the configured time zone.

    The job turns its own failures into signals and returns normally; only then is the day marked done.
    """

    name: str
    at: time
    run: Callable[[datetime], Awaitable[None]]
    weekday: int | None = None


@dataclass(frozen=True)
class Section:
    """A heading in the daily or weekly report and the checks whose lines go under it, in order."""

    title: str
    checks: tuple["Check", ...]


class Check(Protocol):
    def report_kinds(self) -> list[ReportKind]:
        """Report kinds this check reads; each one is also watched for missing runs."""
        ...

    def scheduled(self) -> list[Scheduled]: ...

    async def on_report(self, report: HostReport) -> None:
        """Evaluate a report of one of this check's kinds right after it was stored."""
        ...

    async def periodic(self, now: datetime) -> None:
        """Runs every few minutes, for verdicts that depend on data from several sources."""
        ...

    async def daily_lines(self, now: datetime) -> list[str]:
        """Lines for the daily digest. Say when data is missing; never report "all good" without data."""
        ...

    async def weekly_lines(self, now: datetime) -> list[str]: ...


class CheckBase:
    """Defaults for the parts a check does not use."""

    def report_kinds(self) -> list[ReportKind]:
        return []

    def scheduled(self) -> list[Scheduled]:
        return []

    async def on_report(self, report: HostReport) -> None:
        return None

    async def periodic(self, now: datetime) -> None:
        return None

    async def daily_lines(self, now: datetime) -> list[str]:
        return []

    async def weekly_lines(self, now: datetime) -> list[str]:
        return []
