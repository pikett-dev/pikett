"""The daily and weekly security report as the wired service builds them."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.config import Settings
from app.jobs import Jobs
from app.security.wiring import build_security
from tests.fakes import EN, Clock
from tests.security_helpers import report
from tests.test_security_patches import data as patch_data

TEST, OPS = "app-1", "ops-server"
# Monday 2026-11-16, 08:00 Vienna.
MONDAY = datetime(2026, 11, 16, 7, 0, tzinfo=UTC)


def offline(request: httpx.Request) -> httpx.Response:
    return httpx.Response(503)


@pytest.fixture
async def wired(sessions, service, chat):
    clock = Clock(MONDAY - timedelta(hours=5))  # 03:40, when the collectors report
    settings = Settings(security_hosts=[TEST, OPS], self_rebooting_hosts=[OPS], timezone="Europe/Vienna")
    async with httpx.AsyncClient(transport=httpx.MockTransport(offline)) as client:
        security, _ = build_security(settings, sessions, service, clock, client, chat)
        yield security, clock


async def test_the_daily_report_orders_vulnerabilities_patches_and_backup_and_names_what_is_missing(wired):
    security, clock = wired
    collected = clock.now
    log = patch_data()["log"].replace("2026-11-14", "2026-11-16")
    await security.ingest(report(TEST, "patches", collected, **patch_data(log=log, reboot_required=False)))
    vuln = {"id": "CVE-2026-1", "package": "openssl", "installed": "3.0.2", "fixed": "3.0.15", "severity": "HIGH"}
    trivy = [{"image": "postgres:18", "containers": ["db"], "vulnerabilities": [vuln]}]
    await security.ingest(report(TEST, "trivy", collected, images=trivy))

    lines = await security.daily_lines(MONDAY)

    headings = [line for line in lines if line.startswith("_")]
    assert headings == ["_Vulnerabilities_", "_Overnight patches_", "_Backup_"]
    text = "\n".join(lines)
    assert "*Vulnerabilities (1):* 1 HIGH" in text
    assert "KEV/EPSS: not fetched recently (never)" in text  # the ranking has no data yet
    assert "Trivy (ops-server): no scan has arrived yet" in text
    assert "OSV: no repos or no Bitbucket token configured" in text
    assert "Patches (app-1): 3 package(s)" in text
    assert "Patches (ops-server): no report from last night" in text
    assert "Backup: no databases or no Coolify token configured" in text


async def test_the_weekly_report_shows_trends_and_names_what_is_missing(wired):
    security, clock = wired
    lynis = "hardening_index={}\nwarning[]=AUTH-9286|Weak password policy|-|-|"
    for weeks_ago, score in [(2, 60), (1, 63), (0, 65)]:
        at = clock.now - timedelta(weeks=weeks_ago)
        await security.ingest(report(TEST, "lynis", at, report=lynis.format(score)))

    lines = await security.weekly_lines(MONDAY)

    headings = [line for line in lines if line.startswith("_")]
    assert headings == ["_Vulnerabilities_", "_Hardening (Lynis)_", "_Attacks and logins_", "_Updates_"]
    text = "\n".join(lines)
    assert "No open vulnerabilities (provided the scans ran)." in text
    assert "Lynis (app-1): score 65 (+2 vs. last week), trend 60 → 63 → 65" in text
    assert "Lynis (ops-server): no run in the last 8 days" in text
    assert "CrowdSec (app-1): no data from the last week" in text
    assert "SSH (app-1): no login data from the last week" in text
    assert "the check for newer images has never run" in text
    assert "Coolify: no API token configured" in text
    assert "all good" not in text.lower()


async def test_the_weekly_report_is_posted_on_monday(wired, sessions, service, chat):
    security, _ = wired
    jobs = Jobs(
        service,
        chat,
        sessions,
        Clock(MONDAY),
        "http://ops.test",
        None,
        httpx.AsyncClient(),
        security=security,
        locale=EN,
    )

    await jobs.run_scheduled()

    weekly = [text for text in chat.ops if text.startswith("*Weekly report*")]
    assert len(weekly) == 1 and "_Hardening (Lynis)_" in weekly[0]
    assert any(text.startswith("*Daily report*") and "*Security*" in text for text in chat.ops)
