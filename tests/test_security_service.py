from datetime import UTC, datetime, time, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.config import Settings
from app.incidents.schemas import AlertIn
from app.jobs import Jobs
from app.main import create_app
from app.models import HostReport
from app.schedule import run_if_due
from app.security import overview
from app.security.base import CheckBase, ReportKind, Scheduled
from app.security.lines import Line
from app.security.service import SecurityService
from app.security.signals import Signal, Signals
from tests.fakes import ALICE, BOB, EN, START, TZ, Clock, FakeChat, FakePager
from tests.security_helpers import open_incidents, report


class Probe(CheckBase):
    """A check that expects one kind from two hosts and remembers what it saw."""

    def __init__(self, *, fail: bool = False) -> None:
        self.seen: list[str] = []
        self.fail = fail

    def report_kinds(self):
        return [ReportKind("probe", ("a", "b"), timedelta(hours=2))]

    async def on_report(self, report):
        if self.fail:
            raise RuntimeError("boom")
        self.seen.append(report.host)

    async def daily_lines(self, now):
        return ["probe line"]


@pytest.fixture
def signals(sessions, service, clock):
    return Signals(sessions, service, clock)


async def test_reports_are_stored_and_handed_to_the_check(sessions, signals, clock):
    probe = Probe()
    security = SecurityService(sessions, signals, clock, [probe], locale=EN)

    await security.ingest(report("a", "probe", clock.now, x=1))

    assert probe.seen == ["a"]
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(HostReport)) == 1


async def test_a_failing_check_keeps_the_report(sessions, signals, clock):
    security = SecurityService(sessions, signals, clock, [Probe(fail=True)], locale=EN)

    await security.ingest(report("a", "probe", clock.now))

    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(HostReport)) == 1


async def test_a_missing_report_opens_a_p2_per_host_and_kind_and_closes_when_it_arrives(sessions, signals, clock):
    security = SecurityService(sessions, signals, clock, [Probe()], locale=EN)
    await security.ingest(report("a", "probe", clock.now))

    clock.advance(timedelta(hours=1))
    await security.check_freshness()
    assert await open_incidents(sessions) == []

    clock.advance(timedelta(hours=2))
    await security.check_freshness()
    incidents = await open_incidents(sessions, "HostReportMissing")
    assert sorted(i.labels["host"] for i in incidents) == ["a", "b"]
    assert {i.severity for i in incidents} == {"P2"}
    assert "(never)" in next(i for i in incidents if i.labels["host"] == "b").annotations["summary"]

    await security.ingest(report("a", "probe", clock.now))
    await security.check_freshness()
    assert [i.labels["host"] for i in await open_incidents(sessions)] == ["b"]


async def test_the_stale_cleanup_for_vmalert_leaves_internal_incidents_alone(sessions, signals, service, clock):
    await signals.set("BackupTooOld", "P1", {"host": "a"}, Signal(labels={"host": "a"}, summary="alt"))
    clock.advance(timedelta(minutes=30))
    await service.handle_alerts([AlertIn(labels={"alertname": "Watchdog"})])  # vmalert is alive
    await service.tick()

    assert [i.title for i in await open_incidents(sessions)] == ["BackupTooOld"]


async def test_reconcile_only_resolves_within_its_scope(sessions, signals):
    await signals.set("X", "P2", {"host": "a"}, Signal(labels={"host": "a"}, summary="a"))
    await signals.set("X", "P2", {"host": "b"}, Signal(labels={"host": "b"}, summary="b"))

    await signals.set("X", "P2", {"host": "a"}, None)

    assert [i.labels["host"] for i in await open_incidents(sessions)] == ["b"]


async def test_a_signal_outside_its_scope_is_a_bug(signals):
    with pytest.raises(ValueError, match="outside the scope"):
        await signals.set("X", "P2", {"host": "a"}, Signal(labels={"host": "b"}, summary="b"))


async def test_run_if_due_runs_once_per_day_and_weekly_only_on_its_weekday(sessions):
    ran: list[datetime] = []

    async def job(now):
        ran.append(now)

    monday_9 = datetime(2026, 11, 16, 8, 0, tzinfo=UTC)  # 09:00 Vienna
    assert await run_if_due(sessions, "w", monday_9, time(8, 0), job, weekday=0, tz=TZ)
    assert not await run_if_due(sessions, "w", monday_9 + timedelta(hours=1), time(8, 0), job, weekday=0, tz=TZ)
    assert not await run_if_due(sessions, "w", monday_9 + timedelta(days=1), time(8, 0), job, weekday=0, tz=TZ)
    assert await run_if_due(sessions, "w", monday_9 + timedelta(days=7), time(8, 0), job, weekday=0, tz=TZ)
    assert len(ran) == 2


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (Line("Patches (app-1): 3 package(s); :repeat: server reboot needed", needs_action=True), overview.WARN),
        (
            Line("Patches (app-1): the text mentions :repeat: and needs a manual restart", needs_action=False),
            overview.OK,
        ),
        ("Patches (app-1): 3 Paket(e); braucht Neustart von Hand: docker.service", overview.WARN),  # legacy German
        ("Patches (app-1): 3 package(s); needs a manual restart: docker.service", overview.WARN),  # legacy English
        ("• newer version available: postgres:18 (db)", overview.WARN),
        ("Patches (app-1): no security updates", overview.OK),
    ],
    ids=["flag-true", "flag-false-with-marker", "legacy-german", "legacy-english", "legacy-image", "plain-ok"],
)
def test_a_line_needs_action_by_its_flag_and_a_plain_string_by_its_legacy_markers(line, expected):
    assert overview._line_state([line]) == expected


async def test_the_digest_carries_the_security_section(sessions, signals, service, chat):
    security = SecurityService(sessions, signals, Clock(START), [Probe()], locale=EN)
    clock = Clock(datetime(2026, 10, 20, 6, 0, tzinfo=UTC))
    jobs = Jobs(
        service, chat, sessions, clock, "http://ops.test", None, httpx.AsyncClient(), security=security, locale=EN
    )

    await jobs.run_scheduled()

    assert "*Security*\nprobe line" in chat.ops[0]


async def test_the_weekly_report_goes_out_on_monday(sessions, signals, service, chat):
    security = SecurityService(sessions, signals, Clock(START), [Probe()], locale=EN)
    clock = Clock(datetime(2026, 10, 19, 7, 0, tzinfo=UTC))  # Monday 09:00 Vienna
    jobs = Jobs(
        service, chat, sessions, clock, "http://ops.test", None, httpx.AsyncClient(), security=security, locale=EN
    )

    await jobs.run_scheduled()

    assert any(text.startswith("*Weekly report*") for text in chat.ops)


# ---- the endpoint --------------------------------------------------------------------------------------------------

BODY = {
    "host": "app-1",
    "kind": "patches",
    "collected_at": "2026-10-19T09:00:00Z",
    "data": {"log": "", "health": []},
}


def make_client(database_url, **settings):
    base = Settings(
        database_url=database_url,
        base_url="http://ops.test",
        oncall_people=[ALICE, BOB],
        timezone="Europe/Vienna",
        **settings,
    )
    return TestClient(create_app(base, chat=FakeChat(), pager=FakePager(), clock=Clock(START)))


def test_host_reports_need_the_token(database_url, sessions):
    tokens = {"app-1": "s3cret", "ops-server": "other"}
    with make_client(database_url, host_report_tokens=tokens, security_hosts=["app-1"]) as client:
        assert client.post("/api/v1/host-reports", json=BODY).status_code == 401
        wrong = {"Authorization": "Bearer nope"}
        assert client.post("/api/v1/host-reports", json=BODY, headers=wrong).status_code == 401
        other_host = {"Authorization": "Bearer other"}  # the ops server's token cannot report for the test server
        assert client.post("/api/v1/host-reports", json=BODY, headers=other_host).status_code == 401
        unknown = {**BODY, "host": "app-3"}
        assert client.post("/api/v1/host-reports", json=unknown, headers=other_host).status_code == 401
        good = {"Authorization": "Bearer s3cret"}
        assert client.post("/api/v1/host-reports", json=BODY, headers=good).status_code == 202
        nonsense = {**BODY, "kind": "nonsense"}
        assert client.post("/api/v1/host-reports", json=nonsense, headers=good).status_code == 422
        bad_host = {**BODY, "host": "../etc"}
        assert client.post("/api/v1/host-reports", json=bad_host, headers=good).status_code == 422


def test_host_reports_are_refused_without_a_configured_token(database_url, sessions):
    with make_client(database_url) as client:
        response = client.post("/api/v1/host-reports", json=BODY, headers={"Authorization": "Bearer x"})
        assert response.status_code == 503


class Crashing(CheckBase):
    """A check that trips over the collector's data and a nightly job that fails."""

    def __init__(self) -> None:
        self.runs = 0

    def report_kinds(self):
        return [ReportKind("probe", ("a",), timedelta(hours=2))]

    def scheduled(self):
        return [Scheduled("feed", time(6, 0), self.job)]

    async def on_report(self, report):
        if report.data.get("health") == "not a list":
            raise TypeError("string indices must be integers")

    async def job(self, now):
        self.runs += 1
        raise KeyError("epss")


async def test_a_report_a_check_cannot_read_opens_a_p2_until_a_good_one_arrives(sessions, signals, clock):
    security = SecurityService(sessions, signals, clock, [Crashing()], locale=EN)

    await security.ingest(report("a", "probe", clock.now, health="not a list"))
    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.labels["kind"]) == ("HostReportInvalid", "probe")
    assert "TypeError" in incident.annotations["summary"]

    await security.ingest(report("a", "probe", clock.now, health=[]))
    assert await open_incidents(sessions) == []


async def test_a_failing_job_opens_a_p2_and_does_not_run_again_the_same_day(sessions, signals, service, chat):
    crashing = Crashing()
    security = SecurityService(sessions, signals, Clock(START), [crashing], locale=EN)
    clock = Clock(datetime(2026, 10, 20, 6, 0, tzinfo=UTC))  # 08:00 Vienna
    jobs = Jobs(
        service, chat, sessions, clock, "http://ops.test", None, httpx.AsyncClient(), security=security, locale=EN
    )

    await jobs.run_scheduled()
    clock.advance(timedelta(minutes=1))
    await jobs.run_scheduled()

    assert crashing.runs == 1
    [incident] = await open_incidents(sessions, "ScheduledJobFailed")
    assert incident.labels["job"] == "feed" and "KeyError" in incident.annotations["summary"]


async def test_a_digest_that_cannot_be_posted_does_not_hold_up_the_jobs(sessions, signals, service, chat):
    crashing = Crashing()
    security = SecurityService(sessions, signals, Clock(START), [crashing], locale=EN)

    class DownChat(type(chat)):
        async def post_ops(self, text):
            raise RuntimeError("slack is down")

    down = DownChat()
    clock = Clock(datetime(2026, 10, 20, 6, 0, tzinfo=UTC))
    jobs = Jobs(
        service, down, sessions, clock, "http://ops.test", None, httpx.AsyncClient(), security=security, locale=EN
    )

    await jobs.run_scheduled()

    assert crashing.runs == 1
