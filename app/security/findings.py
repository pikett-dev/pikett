"""Vulnerability findings from Trivy (running images) and OSV (repository dependencies), and how they are listed."""

from collections import Counter
from collections.abc import Iterable, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import VulnerabilityFinding
from app.security.base import CheckBase
from app.security.intel import epss_scores, kev_cves

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
# How many single findings the daily digest names; the counts cover the rest.
DIGEST_ITEMS = 10
# Rows per INSERT; 13 columns each stays far below Postgres' limit of 32767 parameters.
INSERT_BATCH = 1000


def normalize_severity(value: str | None) -> str:
    upper = (value or "").upper()
    return upper if upper in SEVERITY_RANK else "UNKNOWN"


def cve_of(vuln_id: str, aliases: Iterable[str] = ()) -> str | None:
    """The CVE id of a vulnerability, from its own id or its aliases (OSV names many by GHSA id)."""
    for candidate in (vuln_id, *aliases):
        if candidate.startswith("CVE-"):
            return candidate
    return None


@dataclass(frozen=True)
class Finding:
    target: str
    package: str
    installed_version: str
    vuln_id: str
    severity: str
    fixed_version: str = ""
    title: str = ""
    cve: str | None = None
    services: str = ""


async def replace_findings(
    session: AsyncSession,
    source: str,
    scope: str,
    findings: list[Finding],
    now: datetime,
    *,
    keep_targets: Iterable[str] = (),
) -> None:
    """Make the stored findings of (source, scope) the given ones.

    Targets in `keep_targets` could not be scanned this time: their old rows stay as they are, because nothing new
    is known about them.
    """
    rows: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for f in findings:
        # Trivy lists a package twice when it sits in two layers or paths; the first one counts.
        rows.setdefault(
            (f.target, f.package, f.installed_version, f.vuln_id),
            {
                "source": source,
                "scope": scope,
                "target": f.target,
                "package": f.package,
                "installed_version": f.installed_version,
                "vuln_id": f.vuln_id,
                "services": f.services,
                "cve": f.cve,
                "severity": normalize_severity(f.severity),
                "fixed_version": f.fixed_version,
                "title": f.title[:300],
                "first_seen_at": now,
                "last_seen_at": now,
            },
        )
    values = list(rows.values())
    for start in range(0, len(values), INSERT_BATCH):
        statement = insert(VulnerabilityFinding).values(values[start : start + INSERT_BATCH])
        updated = ("services", "cve", "severity", "fixed_version", "title", "last_seen_at")
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=["source", "scope", "target", "package", "installed_version", "vuln_id"],
                set_={name: statement.excluded[name] for name in updated},
            )
        )
    await session.execute(
        delete(VulnerabilityFinding).where(
            VulnerabilityFinding.source == source,
            VulnerabilityFinding.scope == scope,
            VulnerabilityFinding.last_seen_at < now,
            VulnerabilityFinding.target.not_in(list(keep_targets)),
        )
    )


async def all_findings(session: AsyncSession) -> list[VulnerabilityFinding]:
    return list((await session.scalars(select(VulnerabilityFinding))).all())


def rank(findings: list[VulnerabilityFinding], kev: set[str], epss: dict[str, Decimal]) -> list[VulnerabilityFinding]:
    """Actively exploited first (KEV), then by EPSS (likelihood of exploitation), then by severity."""

    def key(f: VulnerabilityFinding) -> tuple[bool, Decimal, int, str, str, str]:
        return (
            f.cve not in kev,
            -epss.get(f.cve or "", Decimal(0)),
            SEVERITY_RANK[f.severity],
            f.vuln_id,
            f.scope,
            f.target,
        )

    return sorted(findings, key=key)


def describe(
    locale: Locale,
    f: VulnerabilityFinding,
    kev: AbstractSet[str] = frozenset(),
    epss: Mapping[str, Decimal] | None = None,
) -> str:
    where = f"{f.services or f.target} ({f.scope})" if f.source == "trivy" else f"{f.scope}: {f.target}"
    fix = f" → {f.fixed_version}" if f.fixed_version else locale.t("security.findings.no_fix")
    marks = ""
    if f.cve in kev:
        marks += " :rotating_light: KEV"
    if f.cve and epss and f.cve in epss:
        marks += f" EPSS {float(epss[f.cve]) * 100:.0f} %"
    return f"{f.severity}{marks} {f.vuln_id} {f.package} {f.installed_version}{fix} in {where}"


class FindingsReport(CheckBase):
    """The list of open vulnerabilities in the daily digest, over all scanners."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession], *, locale: Locale) -> None:
        self._locale = locale
        self._sessions = sessions

    async def daily_lines(self, now: datetime) -> list[str]:
        async with self._sessions() as session:
            findings = await all_findings(session)
            kev = await kev_cves(session)
            epss = await epss_scores(session)
        if not findings:
            return [self._locale.t("security.findings.none")]
        counts = Counter(f.severity for f in findings)
        summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
        exploited = sum(1 for f in findings if f.cve in kev)
        if exploited:
            summary += self._locale.t("security.findings.exploited", n=exploited)
        ranked = rank(findings, kev, epss)
        lines = [self._locale.t("security.findings.head", n=len(findings), summary=summary)]
        lines += [f"• {describe(self._locale, f, kev, epss)}" for f in ranked[:DIGEST_ITEMS]]
        if len(ranked) > DIGEST_ITEMS:
            lines.append(self._locale.t("security.findings.more", n=len(ranked) - DIGEST_ITEMS))
        return lines

    async def weekly_lines(self, now: datetime) -> list[str]:
        """How many findings are open and how many are new this week (first seen in the last 7 days)."""
        async with self._sessions() as session:
            findings = await all_findings(session)
            kev = await kev_cves(session)
        new = [f for f in findings if f.first_seen_at >= now - timedelta(days=7)]
        if not findings:
            return [self._locale.t("security.findings.weekly_none")]
        exploited = sum(1 for f in findings if f.cve in kev)
        by_source = Counter(f.source for f in findings)
        sources = ", ".join(f"{name} {by_source[name]}" for name in ("trivy", "osv") if by_source[name])
        line = self._locale.t("security.findings.weekly", n=len(findings), sources=sources, new=len(new))
        if exploited:
            line += self._locale.t("security.findings.weekly_exploited", n=exploited)
        return [line]
