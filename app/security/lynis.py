"""Lynis hardening audit, weekly with a score trend.

The collector runs `lynis audit system --cronjob` on Sunday 04:30 and sends the lines of /var/log/lynis-report.dat
that matter here (kind `lynis`): `hardening_index=`, `warning[]=ID|text|...`, `suggestion[]=...`. The reports stay
for a year in host_report, which is the score per week.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import HostReport
from app.security import hostreports
from app.security.base import CheckBase, ReportKind
from app.security.signals import Signal, Signals

KIND = "lynis"
FAILED = "LynisFailed"
REPORT_EVERY = timedelta(days=8)
TREND_WEEKS = 6


@dataclass
class LynisResult:
    score: int | None = None
    version: str = ""
    warnings: dict[str, str] = field(default_factory=dict)  # test id -> text
    suggestions: int = 0


def parse_report(text: str) -> LynisResult:
    result = LynisResult()
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key == "hardening_index" and value.strip().isdigit():
            result.score = int(value)
        elif key == "lynis_version":
            result.version = value.strip()
        elif key == "warning[]":
            test_id, _, rest = value.partition("|")
            result.warnings[test_id] = rest.split("|", 1)[0]
        elif key == "suggestion[]":
            result.suggestions += 1
    return result


class LynisCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        hosts: list[str],
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._hosts = tuple(hosts)

    def report_kinds(self) -> list[ReportKind]:
        return [ReportKind(KIND, self._hosts, REPORT_EVERY)]

    async def on_report(self, report: HostReport) -> None:
        scope = {"host": report.host}
        error = hostreports.error_of(report.data)
        if error is None and parse_report(str(report.data.get("report", ""))).score is None:
            error = self._locale.t("security.lynis.no_score")
        signal = (
            Signal(labels=scope, summary=self._locale.t("security.lynis.failed", host=report.host, error=error))
            if error
            else None
        )
        await self._signals.set(FAILED, "P2", scope, signal)

    async def weekly_lines(self, now: datetime) -> list[str]:
        if not self._hosts:
            return [self._locale.t("security.lynis.line.no_hosts")]
        async with self._sessions() as session:
            rows = await hostreports.history(session, KIND, now - timedelta(weeks=TREND_WEEKS + 1))
        lines = []
        for host in self._hosts:
            runs = [
                (row, parse_report(str(row.data.get("report", ""))))
                for row in rows
                if row.host == host and not hostreports.error_of(row.data)
            ]
            runs = [(row, result) for row, result in runs if result.score is not None]
            if not runs or now - runs[-1][0].received_at > REPORT_EVERY:
                lines.append(self._locale.t("security.lynis.line.no_run", host=host))
            if not runs:
                continue
            row, latest = runs[-1]
            trend = " → ".join(str(result.score) for _, result in runs[-TREND_WEEKS:])
            text = self._locale.t("security.lynis.line.score", host=host, score=latest.score)
            if len(runs) > 1:
                previous = runs[-2][1]
                assert latest.score is not None and previous.score is not None  # noqa: S101 (filtered above)
                diff = latest.score - previous.score
                text += self._locale.t(
                    "security.lynis.line.trend", diff=f"{'+' if diff >= 0 else ''}{diff}", trend=trend
                )
                new = {tid: txt for tid, txt in latest.warnings.items() if tid not in previous.warnings}
            else:
                new = latest.warnings
            text += self._locale.t(
                "security.lynis.line.counts", warnings=len(latest.warnings), suggestions=latest.suggestions
            )
            text += self._locale.t("security.lynis.line.run", at=self._locale.day(row.collected_at))
            lines.append(text)
            lines += [
                self._locale.t("security.lynis.line.new_warning", id=tid, text=txt) for tid, txt in sorted(new.items())
            ]
        return lines
