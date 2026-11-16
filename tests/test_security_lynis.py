from datetime import timedelta

import pytest

from app.security.lynis import LynisCheck, parse_report
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import EN
from tests.security_helpers import open_incidents, report

HOST = "app-1"


def lynis(score: int, *warnings: str) -> str:
    lines = ["lynis_version=3.0.9", f"hardening_index={score}", "suggestion[]=SSH-7408|Harden SSH|-|-|"]
    lines += [f"warning[]={w}|Warning text of {w}|-|-|" for w in warnings]
    return "\n".join(lines)


@pytest.fixture
def security(sessions, service, clock):
    signals = Signals(sessions, service, clock)
    return SecurityService(
        sessions, signals, clock, [LynisCheck(sessions, signals, clock, [HOST], locale=EN)], locale=EN
    )


def test_the_report_gives_score_warnings_and_suggestions():
    result = parse_report(lynis(67, "AUTH-9286", "PKGS-7392"))

    assert (result.score, result.version, result.suggestions) == (67, "3.0.9", 1)
    assert result.warnings == {"AUTH-9286": "Warning text of AUTH-9286", "PKGS-7392": "Warning text of PKGS-7392"}


async def test_the_weekly_report_shows_the_trend_and_new_warnings(security, clock):
    for score, warnings in [(62, ["A-1"]), (64, ["A-1"]), (66, ["A-1", "B-2"])]:
        await security.ingest(report(HOST, "lynis", clock.now, report=lynis(score, *warnings)))
        clock.advance(timedelta(weeks=1))

    lines = await security.weekly_lines(clock.now - timedelta(days=6))

    assert lines[0].startswith("Lynis (app-1): score 66 (+2 vs. last week), trend 62 → 64 → 66")
    assert "2 warning(s), 1 suggestions" in lines[0]
    assert lines[1:] == ["• new warning B-2: Warning text of B-2"]


async def test_a_missing_run_reports_itself(security, sessions, clock):
    await security.ingest(report(HOST, "lynis", clock.now, report=lynis(60)))
    clock.advance(timedelta(days=9))

    lines = await security.weekly_lines(clock.now)
    assert lines[0] == ":warning: Lynis (app-1): no run in the last 8 days."

    await security.check_freshness()
    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.labels["kind"]) == ("HostReportMissing", "lynis")


async def test_a_failed_run_is_a_p2(security, sessions, clock):
    await security.ingest(report(HOST, "lynis", clock.now, error="lynis is not installed"))

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("LynisFailed", "P2")

    await security.ingest(report(HOST, "lynis", clock.now, report=lynis(60)))
    assert await open_incidents(sessions) == []


async def test_no_run_yet(security, clock):
    assert await security.weekly_lines(clock.now) == [":warning: Lynis (app-1): no run in the last 8 days."]
