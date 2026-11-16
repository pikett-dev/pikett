from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import VulnerabilityFinding
from app.security.findings import FindingsReport
from app.security.service import SecurityService
from app.security.signals import Signals
from app.security.trivy import TrivyCheck
from tests.fakes import EN
from tests.security_helpers import open_incidents, report

HOST = "app-1"


def vuln(vid: str, package: str = "openssl", severity: str = "HIGH", fixed: str = "3.0.15") -> dict:
    return {"id": vid, "package": package, "installed": "3.0.2", "fixed": fixed, "severity": severity, "title": "x"}


def image(ref: str, *vulns: dict, containers=("core-123",)) -> dict:
    return {"image": ref, "image_id": f"sha256:{ref}", "containers": list(containers), "vulnerabilities": list(vulns)}


@pytest.fixture
def security(sessions, service, clock):
    signals = Signals(sessions, service, clock)
    checks = [FindingsReport(sessions, locale=EN), TrivyCheck(sessions, signals, clock, [HOST], locale=EN)]
    return SecurityService(sessions, signals, clock, checks, locale=EN)


async def findings(sessions) -> list[VulnerabilityFinding]:
    async with sessions() as session:
        return list((await session.scalars(select(VulnerabilityFinding).order_by(VulnerabilityFinding.id))).all())


async def send(security, clock, **data):
    await security.ingest(report(HOST, "trivy", clock.now, server="http://ops:4954", **data))


async def test_scan_results_become_findings_with_service_cve_and_fixed_version(security, sessions, clock):
    await send(security, clock, images=[image("postgres:18", vuln("CVE-2025-1"), vuln("GHSA-x", "zlib"))])

    rows = await findings(sessions)
    assert [(r.vuln_id, r.cve, r.package, r.fixed_version, r.services) for r in rows] == [
        ("CVE-2025-1", "CVE-2025-1", "openssl", "3.0.15", "core-123"),
        ("GHSA-x", None, "zlib", "3.0.15", "core-123"),
    ]
    assert {r.scope for r in rows} == {HOST}


async def test_the_next_scan_replaces_the_findings_but_keeps_first_seen(security, sessions, clock):
    await send(security, clock, images=[image("postgres:18", vuln("CVE-2025-1"), vuln("CVE-2025-2"))])
    first = clock.now
    clock.advance(timedelta(days=1))
    await send(security, clock, images=[image("postgres:18", vuln("CVE-2025-1"))])

    [row] = await findings(sessions)
    assert row.vuln_id == "CVE-2025-1"
    assert row.first_seen_at == first
    assert row.last_seen_at == clock.now


async def test_an_unreachable_server_reports_itself_and_keeps_the_findings(security, sessions, clock):
    await send(security, clock, images=[image("postgres:18", vuln("CVE-2025-1"))])
    await send(security, clock, error="Trivy-Server http://ops:4954 nicht erreichbar: timed out")

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("VulnScanFailed", "P2")
    assert "nicht erreichbar" in incident.annotations["summary"]
    assert len(await findings(sessions)) == 1

    await send(security, clock, images=[image("postgres:18", vuln("CVE-2025-1"))])
    assert await open_incidents(sessions) == []


async def test_an_image_that_failed_keeps_its_old_findings_and_is_reported(security, sessions, clock):
    await send(security, clock, images=[image("a:1", vuln("CVE-1")), image("b:1", vuln("CVE-2"))])
    clock.advance(timedelta(days=1))
    failed = {"image": "a:1", "containers": ["a"], "error": "no space left on device"}
    await send(security, clock, images=[failed, image("b:1")])

    assert [r.vuln_id for r in await findings(sessions)] == ["CVE-1"]
    [incident] = await open_incidents(sessions)
    assert "a:1" in incident.annotations["summary"] and "no space left" in incident.annotations["summary"]


async def test_daily_lines_sort_by_severity_and_name_missing_scans(security, sessions, clock):
    lines = await security.daily_lines(clock.now)
    assert any("Trivy (app-1): no scan has arrived yet" in line for line in lines)

    await send(
        security,
        clock,
        images=[image("postgres:18", vuln("CVE-LOW", severity="LOW"), vuln("CVE-CRIT", "glibc", "CRITICAL", ""))],
    )
    lines = await security.daily_lines(clock.now)

    assert lines[0] == "*Vulnerabilities (2):* 1 CRITICAL, 1 LOW"
    assert lines[1] == "• CRITICAL CVE-CRIT glibc 3.0.2, no fix in core-123 (app-1)"
    assert lines[2].startswith("• LOW CVE-LOW openssl 3.0.2 → 3.0.15")
    assert not any("Trivy" in line for line in lines)  # the scan itself is fine


async def test_a_capped_image_is_named_in_the_daily_lines(security, sessions, clock):
    capped = {**image("postgres:18", vuln("CVE-CRIT", severity="CRITICAL")), "vulnerabilities_omitted": 37}
    await send(security, clock, images=[capped, image("redis:8", vuln("CVE-LOW", severity="LOW"))])

    lines = await security.daily_lines(clock.now)

    assert any(
        "Trivy (app-1): 1 image(s) list only their most severe findings, 37 lower ones" in line for line in lines
    )
