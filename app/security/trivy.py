"""Trivy scan of the running images.

The collector on each server scans the images of its running containers against the trivy-server on the ops
server and reports (kind `trivy`):

    {"server": url, "images": [{"image", "image_id", "containers": [...], "vulnerabilities": [...],
                                "vulnerabilities_omitted": n}
                               | {"image", "containers", "error"}]}
or {"server": url, "error": ...} when the trivy-server cannot be reached.
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import HostReport
from app.security import hostreports
from app.security.base import CheckBase, ReportKind
from app.security.findings import Finding, cve_of, replace_findings
from app.security.signals import Signal, Signals

KIND = "trivy"
SCAN_FAILED = "VulnScanFailed"
REPORT_EVERY = timedelta(hours=26)


def findings_of(image: dict[str, Any]) -> list[Finding]:
    services = ", ".join(sorted(image.get("containers", [])))
    return [
        Finding(
            target=str(image["image"]),
            services=services,
            package=str(v.get("package", "")),
            installed_version=str(v.get("installed", "")),
            vuln_id=str(v.get("id", "")),
            cve=cve_of(str(v.get("id", ""))),
            severity=str(v.get("severity", "UNKNOWN")),
            fixed_version=str(v.get("fixed", "")),
            title=str(v.get("title", "")),
        )
        for v in image.get("vulnerabilities", [])
        if v.get("id") and v.get("package")
    ]


class TrivyCheck(CheckBase):
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
        scope = {"source": KIND, "host": report.host}
        if error := hostreports.error_of(report.data):
            await self._signals.set(
                SCAN_FAILED,
                "P2",
                scope,
                Signal(
                    labels=scope,
                    summary=self._locale.t("security.trivy.scan_failed", host=report.host, error=error),
                ),
            )
            return  # the findings of the last good scan stay

        images = report.data.get("images", [])
        failed = [img for img in images if img.get("error")]
        findings = [f for img in images if not img.get("error") for f in findings_of(img)]
        async with self._sessions() as session, session.begin():
            await replace_findings(
                session,
                KIND,
                report.host,
                findings,
                self._clock(),
                keep_targets=[str(img.get("image")) for img in failed],
            )

        signal = None
        if failed:
            names = ", ".join(str(img.get("image")) for img in failed[:5])
            more = self._locale.t("security.trivy.more", n=len(failed) - 5) if len(failed) > 5 else ""
            signal = Signal(
                labels=scope,
                summary=self._locale.t(
                    "security.trivy.images_failed",
                    host=report.host,
                    n=len(failed),
                    names=names,
                    more=more,
                    error=str(failed[0]["error"])[:300],
                ),
            )
        await self._signals.set(SCAN_FAILED, "P2", scope, signal)

    async def daily_lines(self, now: datetime) -> list[str]:
        """Only what is wrong with the scans themselves; the findings are listed by FindingsReport."""
        if not self._hosts:
            return [self._locale.t("security.trivy.line.no_hosts")]
        async with self._sessions() as session:
            newest = await hostreports.latest(session, KIND)
        lines = []
        for host in self._hosts:
            row = newest.get(host)
            if row is None:
                lines.append(self._locale.t("security.trivy.line.no_scan", host=host))
            elif now - row.received_at > REPORT_EVERY:
                lines.append(
                    self._locale.t("security.trivy.line.last_scan", host=host, at=self._locale.day(row.collected_at))
                )
            elif error := hostreports.error_of(row.data):
                lines.append(self._locale.t("security.trivy.line.failed", host=host, error=error[:200]))
            elif failed := [img for img in row.data.get("images", []) if img.get("error")]:
                lines.append(self._locale.t("security.trivy.line.images_failed", host=host, n=len(failed)))
            if row is not None and (
                capped := [i for i in row.data.get("images", []) if i.get("vulnerabilities_omitted")]
            ):
                omitted = sum(n for img in capped if isinstance(n := img["vulnerabilities_omitted"], int))
                lines.append(self._locale.t("security.trivy.line.capped", host=host, n=len(capped), omitted=omitted))
        return lines
