"""Patch window: what unattended-upgrades and needrestart did at 03:00, as the collector reported it at 03:40.

Kind `patches`: {"log": tail of unattended-upgrades.log, "dpkg_log": tail of unattended-upgrades-dpkg.log,
"needrestart": output of `needrestart -b -r l`, "reboot_required": bool, "reboot_packages": [...],
"health": [{"url", "status"} | {"url", "error"}]}.
"""

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import HostReport
from app.security import hostreports
from app.security.base import CheckBase, ReportKind
from app.security.lines import Line
from app.security.reboot import SELF_REBOOT_AT, SELF_REBOOT_DONE_AFTER, next_window
from app.security.signals import Signal, Signals

KIND = "patches"
FAILED = "PatchFailed"
HEALTH_RED = "PatchHealthRed"
MISSED = "PatchWindowMissed"
REPORT_FAILED = "PatchReportFailed"
REPORT_EVERY = timedelta(hours=26)
# The window runs daily; a last run older than this did not happen last night.
RUN_EVERY = timedelta(hours=26)
SHOWN_PACKAGES = 8

_LOG_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (\w+) (.*)$")
_DPKG_START = re.compile(r"^Log started: (\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)")
_RESTART = re.compile(r"^\s*systemctl restart (.+)$")
# `Unattended-Upgrade::Mail` is set but the host has no mailer. unattended-upgrades logs that at ERROR level after the
# upgrade is done; the patches are installed, so it is no failed run.
_NO_MAILER = "can not send mail"


@dataclass
class PatchRun:
    started_at: datetime | None = None
    packages: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _local(stamp: str, tz: tzinfo) -> datetime:
    """The servers keep their logs in the configured time zone (cloud-init sets it to the same one)."""
    return datetime.fromisoformat(stamp).replace(tzinfo=tz)


def parse_run(log: str, tz: tzinfo) -> PatchRun:
    """The last run of unattended-upgrades in its log."""
    run = PatchRun()
    for line in log.splitlines():
        match = _LOG_LINE.match(line)
        if not match:
            continue
        stamp, level, text = match.groups()
        if "Starting unattended upgrades script" in text:
            run = PatchRun(started_at=_local(stamp, tz))
        elif text.startswith("Packages that will be upgraded:"):
            run.packages += text.split(":", 1)[1].split()
        elif (level in ("ERROR", "CRITICAL") and _NO_MAILER not in text) or "upgrades failed" in text.lower():
            run.errors.append(text[:300])
    return run


def restarted_services(dpkg_log: str, since: datetime | None, tz: tzinfo) -> list[str]:
    """Services needrestart restarted during dpkg runs that started at or after `since`."""
    services: list[str] = []
    current = False
    for line in dpkg_log.splitlines():
        if match := _DPKG_START.match(line):
            current = since is not None and _local(f"{match[1]} {match[2]}", tz) >= since - timedelta(minutes=1)
        elif current and (restart := _RESTART.match(line)):
            services += [s for s in restart[1].split() if s not in services]
    return services


def pending_services(needrestart: str) -> list[str]:
    """Services that still run old code: needrestart did not restart them (excluded, like docker)."""
    return [line.split(":", 1)[1].strip() for line in needrestart.splitlines() if line.startswith("NEEDRESTART-SVC:")]


def unhealthy(locale: Locale, health: list[dict[str, Any]]) -> list[str]:
    bad = []
    for check in health:
        status = check.get("status")
        if not isinstance(status, int) or not 200 <= status < 300:
            bad.append(f"{check.get('url')} ({status or check.get('error', locale.t('security.patch.no_result'))})")
    return bad


RebootListener = Callable[[HostReport], Awaitable[None]]


class PatchCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        hosts: list[str],
        *,
        self_rebooting: list[str],
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._hosts = tuple(hosts)
        self._self_rebooting = frozenset(self_rebooting)
        self._reboot_listeners: list[RebootListener] = []

    def on_reboot_state(self, listener: RebootListener) -> None:
        """Called with every patches report, so the reboot question sees `reboot_required`."""
        self._reboot_listeners.append(listener)

    def report_kinds(self) -> list[ReportKind]:
        return [ReportKind(KIND, self._hosts, REPORT_EVERY)]

    async def on_report(self, report: HostReport) -> None:
        scope = {"host": report.host}
        if error := hostreports.error_of(report.data):
            summary = self._locale.t("security.patch.report_incomplete", host=report.host, error=error)
            await self._signals.set(REPORT_FAILED, "P2", scope, Signal(labels=scope, summary=summary))
            return
        await self._signals.set(REPORT_FAILED, "P2", scope, None)

        run = parse_run(str(report.data.get("log", "")), self._locale.tz)
        missed = None
        if run.started_at is None or report.collected_at - run.started_at > RUN_EVERY:
            last = (
                self._locale.t("security.patch.last", at=self._locale.day_time(run.started_at))
                if run.started_at
                else self._locale.t("security.patch.no_run")
            )
            missed = Signal(
                labels=scope,
                summary=self._locale.t("security.patch.window_missed", host=report.host, last=last),
            )
        await self._signals.set(MISSED, "P2", scope, missed)

        failed = None
        if run.errors and not missed:
            failed = Signal(
                labels=scope,
                summary=self._locale.t("security.patch.failed", host=report.host, error=run.errors[0]),
                details={"errors": " | ".join(run.errors[:5])},
            )
        await self._signals.set(FAILED, "P1", scope, failed)

        bad = unhealthy(self._locale, report.data.get("health") or [])
        health = None
        if bad:
            health = Signal(
                labels=scope,
                summary=self._locale.t("security.patch.health_red", host=report.host, bad=", ".join(bad)),
            )
        await self._signals.set(HEALTH_RED, "P1", scope, health)

        for listener in self._reboot_listeners:
            await listener(report)

    async def daily_lines(self, now: datetime) -> list[str]:
        if not self._hosts:
            return [self._locale.t("security.patch.line.no_hosts")]
        async with self._sessions() as session:
            newest = await hostreports.latest(session, KIND)
        lines = []
        for host in self._hosts:
            row = newest.get(host)
            if row is None or now - row.received_at > REPORT_EVERY:
                lines.append(self._locale.t("security.patch.line.no_report", host=host))
                continue
            if error := hostreports.error_of(row.data):
                lines.append(self._locale.t("security.patch.line.incomplete", host=host, error=error))
                continue
            lines.append(self._line(host, row, now))
        return lines

    def _reboot_overtaken(self, host: str, row: HostReport, now: datetime) -> bool:
        """The report asked for a reboot that the server does by itself: its cron job restarts it on Sunday 05:00 when
        `reboot-required` exists, which is after the 03:40 report. From then on the report is out of date until the
        next one; it cannot say whether the reboot ran, so the line only says it was due."""
        if host not in self._self_rebooting or not row.data.get("reboot_required"):
            return False
        return now >= next_window(row.collected_at, self._locale.tz, SELF_REBOOT_AT) + SELF_REBOOT_DONE_AFTER

    def _line(self, host: str, row: HostReport, now: datetime) -> Line:
        t = self._locale.t
        run = parse_run(str(row.data.get("log", "")), self._locale.tz)
        if run.started_at is None or row.collected_at - run.started_at > RUN_EVERY:
            return Line(t("security.patch.line.not_run", host=host))
        if run.errors:
            text = t("security.patch.line.failed", host=host, error=run.errors[0])
        elif run.packages:
            shown = ", ".join(run.packages[:SHOWN_PACKAGES])
            extra = len(run.packages) - SHOWN_PACKAGES
            more = t("security.patch.line.more", n=extra) if extra > 0 else ""
            text = t("security.patch.line.packages", host=host, n=len(run.packages), shown=shown, more=more)
        else:
            text = t("security.patch.line.none", host=host)
        action = False
        restarted = restarted_services(str(row.data.get("dpkg_log", "")), run.started_at, self._locale.tz)
        if restarted:
            text += t("security.patch.line.restarted", services=", ".join(restarted))
        if self._reboot_overtaken(host, row, now):
            text += t("security.patch.line.reboot_planned")
        else:
            if pending := pending_services(str(row.data.get("needrestart", ""))):
                text += t("security.patch.line.pending", services=", ".join(pending))
                action = True
            if row.data.get("reboot_required"):
                text += t("security.patch.line.reboot_required")
                action = True
        if bad := unhealthy(self._locale, row.data.get("health") or []):
            text += t("security.patch.line.health_red", bad=", ".join(bad))
        return Line(text, needs_action=action)
