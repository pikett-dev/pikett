"""CISA KEV and EPSS for the findings.

Daily, the service fetches the KEV catalog and the EPSS scores of the CVEs it has findings for. A finding whose CVE
is in KEV (actively exploited) opens a P1 at once, one per CVE and server or repository. A failed fetch keeps the
data of the last good one and opens a P2 for the feed; it never opens or closes a KEV incident by itself.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, Protocol

import httpx
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import last_run
from app.i18n import Locale
from app.models import EpssScore, Incident, KevEntry, VulnerabilityFinding
from app.security.base import CheckBase, Scheduled
from app.security.signals import Signal, Signals

log = logging.getLogger(__name__)

# cisa.gov answers 403 to some data-centre addresses; CISA publishes the same catalog in its GitHub repository.
# The first that works counts.
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_URL = "https://api.first.org/data/v1/epss"
JOB = "vuln_intel"
FETCH_AT = time(6, 0)
EXPLOITED = "ExploitedVulnerability"
FEED_FAILED = "VulnFeedFailed"
# The catalog has well over a thousand entries; a much shorter answer is a broken download, not a new catalog.
MIN_KEV_ENTRIES = 500
# The EPSS API takes at most 2000 characters in its cve parameter.
EPSS_BATCH = 100


class FeedError(Exception):
    pass


@dataclass(frozen=True)
class Kev:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: date | None
    due_date: date | None
    ransomware: str


@dataclass(frozen=True)
class Epss:
    cve: str
    epss: Decimal
    percentile: Decimal
    score_date: date | None


class IntelSource(Protocol):
    async def kev(self) -> list[Kev]: ...

    async def epss(self, cves: list[str]) -> list[Epss]: ...


def _date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)) if value else None
    except ValueError:
        return None


def parse_kev(payload: dict[str, Any]) -> list[Kev]:
    return [
        Kev(
            cve=str(v["cveID"]),
            vendor=str(v.get("vendorProject", "")),
            product=str(v.get("product", "")),
            name=str(v.get("vulnerabilityName", "")),
            date_added=_date(v.get("dateAdded")),
            due_date=_date(v.get("dueDate")),
            ransomware=str(v.get("knownRansomwareCampaignUse", "")),
        )
        for v in payload.get("vulnerabilities") or []
        if str(v.get("cveID", "")).startswith("CVE-")
    ]


def parse_epss(payload: dict[str, Any]) -> list[Epss]:
    return [
        Epss(
            cve=str(row["cve"]),
            epss=Decimal(str(row["epss"])),
            percentile=Decimal(str(row["percentile"])),
            score_date=_date(row.get("date")),
        )
        for row in payload.get("data") or []
    ]


class HttpIntel:
    def __init__(self, client: httpx.AsyncClient, locale: Locale) -> None:
        self._client = client
        self._locale = locale

    async def _get(self, url: str, **params: str) -> dict[str, Any]:
        try:
            response = await self._client.get(url, params=params, timeout=60)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise FeedError(f"{url}: {exc}") from exc
        if not isinstance(payload, dict):
            raise FeedError(self._locale.t("security.intel.unexpected", url=url))
        return payload

    async def kev(self) -> list[Kev]:
        errors = []
        for url in KEV_URLS:
            try:
                entries = parse_kev(await self._get(url))
            except FeedError as exc:
                errors.append(str(exc))
                continue
            if len(entries) >= MIN_KEV_ENTRIES:
                return entries
            errors.append(self._locale.t("security.intel.kev_truncated", url=url, n=len(entries)))
        raise FeedError(" | ".join(errors))

    async def epss(self, cves: list[str]) -> list[Epss]:
        scores: list[Epss] = []
        for start in range(0, len(cves), EPSS_BATCH):
            batch = cves[start : start + EPSS_BATCH]
            scores += parse_epss(await self._get(EPSS_URL, cve=",".join(batch)))
        return scores


async def kev_cves(session: AsyncSession) -> set[str]:
    return set((await session.scalars(select(KevEntry.cve))).all())


async def epss_scores(session: AsyncSession) -> dict[str, Decimal]:
    return {row.cve: row.epss for row in (await session.scalars(select(EpssScore))).all()}


class IntelCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        source: IntelSource,
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._source = source

    def scheduled(self) -> list[Scheduled]:
        return [Scheduled(JOB, FETCH_AT, self.refresh)]

    async def refresh(self, now: datetime) -> None:
        await self._refresh_kev()
        await self._refresh_epss(now)
        # The verdict on exploited CVEs is the periodic step's alone (every 5 minutes), so two reconciles of the
        # same incidents never run side by side.

    async def _feed(self, feed: str, error: Exception | None) -> None:
        scope = {"feed": feed}
        signal = None
        if error is not None:
            summary = self._locale.t("security.intel.feed_failed", feed=feed.upper(), error=error)
            signal = Signal(labels=scope, summary=summary[:500])
        await self._signals.set(FEED_FAILED, "P2", scope, signal)

    async def _refresh_kev(self) -> None:
        try:
            entries = await self._source.kev()
        except FeedError as exc:
            await self._feed("kev", exc)
            return
        async with self._sessions() as session, session.begin():
            await session.execute(delete(KevEntry))
            session.add_all(KevEntry(**vars(entry)) for entry in entries)
        await self._feed("kev", None)

    async def _refresh_epss(self, now: datetime) -> None:
        query = select(VulnerabilityFinding.cve).where(VulnerabilityFinding.cve.is_not(None)).distinct()
        async with self._sessions() as session:
            cves = sorted(cve for cve in (await session.scalars(query)).all() if cve)
        if not cves:
            await self._feed("epss", None)
            return
        try:
            scores = await self._source.epss(cves)
        except FeedError as exc:
            await self._feed("epss", exc)
            return
        async with self._sessions() as session, session.begin():
            for score in scores:
                values = {"epss": score.epss, "percentile": score.percentile, "score_date": score.score_date}
                await session.execute(
                    insert(EpssScore)
                    .values(cve=score.cve, fetched_at=now, **values)
                    .on_conflict_do_update(index_elements=["cve"], set_={**values, "fetched_at": now})
                )
        await self._feed("epss", None)

    async def periodic(self, now: datetime) -> None:
        """One P1 per exploited CVE and server or repository it occurs in; closes when the finding is gone."""
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    select(VulnerabilityFinding, KevEntry)
                    .join(KevEntry, KevEntry.cve == VulnerabilityFinding.cve)
                    .order_by(VulnerabilityFinding.id)
                )
            ).all()
        grouped: dict[tuple[str, str], list[tuple[VulnerabilityFinding, KevEntry]]] = {}
        for finding, kev in rows:
            grouped.setdefault((kev.cve, finding.scope), []).append((finding, kev))
        firing = []
        for (cve, scope), items in grouped.items():
            finding, kev = items[0]
            where = ", ".join(sorted({f.services or f.target for f, _ in items}))
            fixed = finding.fixed_version or self._locale.t("security.intel.none_yet")
            firing.append(
                Signal(
                    labels={"cve": cve, "scope": scope},
                    summary=self._locale.t(
                        "security.intel.exploited",
                        cve=cve,
                        name=kev.name,
                        package=finding.package,
                        version=finding.installed_version,
                        where=where,
                        scope=scope,
                        fixed=fixed,
                    ),
                    link=f"https://nvd.nist.gov/vuln/detail/{cve}",
                )
            )
        await self._signals.reconcile(EXPLOITED, "P1", {}, firing)

    async def daily_lines(self, now: datetime) -> list[str]:
        """Only when the ranking rests on old or missing data; a fresh fetch needs no line."""
        async with self._sessions() as session:
            last = await last_run(session, JOB)
            failing = (
                await session.scalars(
                    select(Incident.labels).where(Incident.status == "open", Incident.title == FEED_FAILED)
                )
            ).all()
        lines = []
        if last is None or now - last > timedelta(hours=26):
            when = (
                self._locale.t("security.common.last", at=self._locale.day(last))
                if last
                else self._locale.t("security.common.never")
            )
            lines.append(self._locale.t("security.intel.line.stale", when=when))
        lines += [
            self._locale.t("security.intel.line.feed_failed", feed=labels.get("feed", "?").upper())
            for labels in failing
        ]
        return lines
