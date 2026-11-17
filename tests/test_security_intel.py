from datetime import date, timedelta
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app.models import EpssScore, KevEntry
from app.security import overview
from app.security.findings import Finding, FindingsReport, replace_findings
from app.security.intel import MIN_KEV_ENTRIES, Epss, FeedError, HttpIntel, IntelCheck, Kev, parse_epss, parse_kev
from app.security.signals import Signals
from tests.fakes import EN
from tests.security_helpers import open_incidents

HOST = "app-1"


def kev(cve: str) -> Kev:
    return Kev(cve, "OpenSSL", "OpenSSL", "OpenSSL Heap Overflow", date(2026, 3, 1), date(2026, 3, 22), "Unknown")


class FakeIntel:
    def __init__(self, kev=None, epss=None):
        self.kev_result = kev if kev is not None else []
        self.epss_result = epss if epss is not None else []
        self.epss_asked: list[list[str]] = []

    async def kev(self):
        if isinstance(self.kev_result, Exception):
            raise self.kev_result
        return self.kev_result

    async def epss(self, cves):
        self.epss_asked.append(cves)
        if isinstance(self.epss_result, Exception):
            raise self.epss_result
        return self.epss_result


@pytest.fixture
def signals(sessions, service, clock):
    return Signals(sessions, service, clock)


async def add_findings(sessions, clock, *findings: Finding, scope=HOST, source="trivy"):
    async with sessions() as session, session.begin():
        await replace_findings(session, source, scope, list(findings), clock.now)


def finding(vuln_id: str, package: str = "openssl", severity: str = "HIGH", **extra) -> Finding:
    args = {"target": "postgres:18", "installed_version": "3.0.2", "fixed_version": "3.0.15", "services": "db"}
    return Finding(package=package, vuln_id=vuln_id, severity=severity, **{"cve": vuln_id, **args, **extra})


async def test_a_finding_in_kev_opens_a_p1_with_cve_service_and_fixed_version(sessions, signals, clock, pager):
    await add_findings(sessions, clock, finding("CVE-2026-1"), finding("CVE-2026-2"))
    check = IntelCheck(sessions, signals, clock, FakeIntel(kev=[kev("CVE-2026-1")]), locale=EN)

    await check.refresh(clock.now)
    assert await open_incidents(sessions) == []  # the verdict is the periodic step's (every 5 minutes)
    await check.periodic(clock.now)

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("ExploitedVulnerability", "P1")
    assert incident.labels["cve"] == "CVE-2026-1" and incident.labels["scope"] == HOST
    summary = incident.annotations["summary"]
    assert "CVE-2026-1" in summary and "in db" in summary and "Fixed version: 3.0.15" in summary
    assert pager.pages == [("Alice", False)]


async def test_a_new_finding_with_a_known_kev_entry_opens_the_p1_without_waiting_for_the_next_fetch(
    sessions, signals, clock
):
    check = IntelCheck(sessions, signals, clock, FakeIntel(kev=[kev("CVE-2026-1")]), locale=EN)
    await check.refresh(clock.now)
    assert await open_incidents(sessions) == []

    await add_findings(sessions, clock, finding("CVE-2026-1"))
    await check.periodic(clock.now)

    assert [i.title for i in await open_incidents(sessions)] == ["ExploitedVulnerability"]


async def test_the_p1_closes_when_the_finding_is_gone(sessions, signals, clock):
    await add_findings(sessions, clock, finding("CVE-2026-1"))
    check = IntelCheck(sessions, signals, clock, FakeIntel(kev=[kev("CVE-2026-1")]), locale=EN)
    await check.refresh(clock.now)
    await check.periodic(clock.now)

    clock.advance(timedelta(days=1))
    await add_findings(sessions, clock)  # the next scan no longer sees it
    await check.periodic(clock.now)

    assert await open_incidents(sessions) == []


async def test_a_failed_feed_reports_itself_keeps_the_old_data_and_raises_no_false_alarm(sessions, signals, clock):
    await add_findings(sessions, clock, finding("CVE-2026-1"))
    intel = FakeIntel(kev=[kev("CVE-2026-1")], epss=[Epss("CVE-2026-1", Decimal("0.9"), Decimal("0.99"), None)])
    check = IntelCheck(sessions, signals, clock, intel, locale=EN)
    await check.refresh(clock.now)
    await check.periodic(clock.now)

    intel.kev_result = FeedError("cisa.gov: 503")
    intel.epss_result = FeedError("api.first.org: timeout")
    await check.refresh(clock.now)
    await check.periodic(clock.now)

    titles = sorted((i.title, i.labels.get("feed", "")) for i in await open_incidents(sessions))
    assert titles == [("ExploitedVulnerability", ""), ("VulnFeedFailed", "epss"), ("VulnFeedFailed", "kev")]
    async with sessions() as session:
        assert (await session.scalars(select(KevEntry.cve))).all() == ["CVE-2026-1"]
        assert (await session.scalar(select(EpssScore.epss))) == Decimal("0.9")

    intel.kev_result, intel.epss_result = [kev("CVE-2026-1")], []
    await check.refresh(clock.now)
    await check.periodic(clock.now)
    assert [i.title for i in await open_incidents(sessions)] == ["ExploitedVulnerability"]


async def test_epss_is_asked_only_for_the_cves_of_the_findings(sessions, signals, clock):
    await add_findings(sessions, clock, finding("CVE-2026-2"), finding("CVE-2026-1"), finding("GHSA-x", cve=None))
    intel = FakeIntel()
    await IntelCheck(sessions, signals, clock, intel, locale=EN).refresh(clock.now)

    assert intel.epss_asked == [["CVE-2026-1", "CVE-2026-2"]]


async def test_the_report_sorts_kev_first_then_epss_then_severity(sessions, signals, clock):
    await add_findings(
        sessions,
        clock,
        finding("CVE-CRIT", severity="CRITICAL"),
        finding("CVE-HIGH-EPSS", "zlib", "HIGH"),
        finding("CVE-LOW-KEV", "glibc", "LOW"),
    )
    epss = [Epss("CVE-HIGH-EPSS", Decimal("0.42"), Decimal("0.97"), None)]
    await IntelCheck(sessions, signals, clock, FakeIntel(kev=[kev("CVE-LOW-KEV")], epss=epss), locale=EN).refresh(
        clock.now
    )

    lines = await FindingsReport(sessions, locale=EN).daily_lines(clock.now)

    assert lines[0] == "*Vulnerabilities (3):* 1 CRITICAL, 1 HIGH, 1 LOW, 1 of them actively exploited (KEV)"
    assert lines[1].startswith("• LOW :rotating_light: KEV CVE-LOW-KEV glibc")
    assert lines[2].startswith("• HIGH EPSS 42 % CVE-HIGH-EPSS zlib")
    assert lines[3].startswith("• CRITICAL CVE-CRIT openssl")


async def test_the_card_is_fresh_from_the_scans_and_asks_for_action_on_a_kev_finding(sessions, signals, clock):
    await add_findings(sessions, clock, finding("CVE-2026-1"))
    report = FindingsReport(sessions, locale=EN)
    started = clock.now - timedelta(days=1)

    [row] = await overview.build(EN, sessions, clock.now, [report], started)
    assert (row.state, row.last_run) == (overview.OK, clock.now)

    await IntelCheck(sessions, signals, clock, FakeIntel(kev=[kev("CVE-2026-1")]), locale=EN).refresh(clock.now)
    [row] = await overview.build(EN, sessions, clock.now, [report], started)
    assert row.state == overview.WARN

    clock.advance(timedelta(hours=30))  # no scan for more than a day
    [row] = await overview.build(EN, sessions, clock.now, [report], started)
    assert row.state == overview.OVERDUE


def test_parsing_the_feeds():
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            },
            {"cveID": "not-a-cve"},
        ]
    }
    assert parse_kev(payload) == [
        Kev(
            "CVE-2021-44228",
            "Apache",
            "Log4j2",
            "Apache Log4j2 Remote Code Execution Vulnerability",
            date(2021, 12, 10),
            date(2021, 12, 24),
            "Known",
        )
    ]
    assert parse_epss(
        {"data": [{"cve": "CVE-1", "epss": "0.95732", "percentile": "0.99721", "date": "2024-04-15"}]}
    ) == [Epss("CVE-1", Decimal("0.95732"), Decimal("0.99721"), date(2024, 4, 15))]


async def test_the_github_copy_of_the_catalog_is_used_when_cisa_gov_refuses():
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.host)
        if request.url.host == "www.cisa.gov":
            return httpx.Response(403)
        return httpx.Response(
            200, json={"vulnerabilities": [{"cveID": f"CVE-2026-{i}"} for i in range(MIN_KEV_ENTRIES)]}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        entries = await HttpIntel(client, EN).kev()

    assert len(entries) == MIN_KEV_ENTRIES
    assert asked == ["www.cisa.gov", "raw.githubusercontent.com"]


async def test_a_truncated_catalog_is_a_feed_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-1"}] * (MIN_KEV_ENTRIES - 1)})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(FeedError, match="truncated.*truncated"):
            await HttpIntel(client, EN).kev()


async def test_epss_is_fetched_in_batches():
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.params["cve"])
        return httpx.Response(200, json={"data": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await HttpIntel(client, EN).epss([f"CVE-2026-{i}" for i in range(150)])

    assert [len(a.split(",")) for a in asked] == [100, 50]


async def test_an_http_error_is_a_feed_error():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        with pytest.raises(FeedError):
            await HttpIntel(client, EN).kev()
