from datetime import UTC, datetime, time, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.activity import timeline
from app.activity.runs import RETENTION, RunLog
from app.config import Settings
from app.jobs import Jobs
from app.main import create_app
from app.models import HostReport, Incident, IncidentAnalysis, OpsRun
from app.security import overview
from app.security.base import CheckBase, ReportKind, Scheduled
from app.security.help import all_help
from app.security.names import CHECK_KEYS
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import ALICE, BOB, EN, START, Clock, FakeChat, FakePager

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


class Probe(CheckBase):
    """A check with one daily job (which can fail), one weekly report kind and a result line."""

    def __init__(self, *, fail: bool = False, line: str = "Probe: all good") -> None:
        self.fail = fail
        self.line = line

    def report_kinds(self):
        return [ReportKind("probe", ("a", "b"), timedelta(hours=26))]

    def scheduled(self):
        async def run(now):
            if self.fail:
                raise RuntimeError("Feed unreachable, contact anna@example.com")

        return [Scheduled("probe_job", time(3, 0), run)]

    async def daily_lines(self, now):
        return [self.line]


def _service(sessions, service, clock, check):
    return SecurityService(sessions, Signals(sessions, service, clock), clock, [check], locale=EN)


async def _scheduled(security, name):
    job = next(job for job in security.scheduled() if job.name == name)
    await job.run(START)


async def _runs(sessions):
    async with sessions() as session:
        return list((await session.scalars(select(OpsRun).order_by(OpsRun.id))).all())


async def test_a_scheduled_job_leaves_a_row_for_success_and_for_failure(sessions, service, clock):
    ok = _service(sessions, service, clock, Probe())
    await _scheduled(ok, "probe_job")
    failing = _service(sessions, service, clock, Probe(fail=True))
    await _scheduled(failing, "probe_job")  # a guarded job returns normally; the history still says it failed

    first, second = await _runs(sessions)
    assert (first.name, first.kind, first.status, first.summary) == ("probe_job", "check", "ok", "Run finished")
    assert (second.status, "Feed unreachable" in second.summary) == ("failed", True)
    assert "anna@example.com" not in second.summary  # the history is shown on a web page: PII stays masked


async def test_the_history_never_breaks_the_job(sessions, clock):
    class Broken:
        def __call__(self):
            raise RuntimeError("database is gone")

    runs = RunLog(Broken(), clock)  # type: ignore[arg-type]

    await runs.record("x", "check", START, ok=True, summary="fine")  # must not raise


async def test_digest_and_weekly_are_recorded_and_a_retry_loop_leaves_one_failure_per_hour(
    sessions, service, chat, clock, monkeypatch
):
    jobs = Jobs(service, chat, sessions, clock, "http://ops.test", None, None, locale=EN)  # type: ignore[arg-type]
    clock.now = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)

    assert await jobs.run_digest_if_due() is True
    assert [(r.name, r.kind, r.status) for r in await _runs(sessions)] == [("digest", "report", "ok")]

    async def broken(now):
        raise RuntimeError("Slack is gone")

    clock.now += timedelta(days=1)
    monkeypatch.setattr(jobs, "_post_digest", broken)
    for _ in range(5):  # the schedule check retries every minute
        with pytest.raises(RuntimeError):
            await jobs.run_digest_if_due()
        clock.now += timedelta(minutes=1)
    failed = [r for r in await _runs(sessions) if r.status == "failed"]
    assert len(failed) == 1


async def test_old_runs_are_pruned_by_the_daily_job(sessions, service, clock):
    security = _service(sessions, service, clock, Probe())
    old = START - RETENTION - timedelta(days=1)
    async with sessions() as session, session.begin():
        session.add(OpsRun(name="old", kind="check", started_at=old, finished_at=old, status="ok", summary=""))
        session.add(OpsRun(name="new", kind="check", started_at=START, finished_at=START, status="ok", summary=""))

    await _scheduled(security, "host_report_prune")

    names = {r.name for r in await _runs(sessions)}
    assert "old" not in names and "new" in names


def test_every_check_of_the_service_has_a_label_on_the_overview():
    import app.security.wiring  # noqa: F401 (imports every check)

    def subclasses(cls):
        for sub in cls.__subclasses__():
            yield sub
            yield from subclasses(sub)

    names = {sub.__name__ for sub in subclasses(CheckBase) if sub.__module__.startswith("app.security")}
    assert names <= set(CHECK_KEYS)


def test_report_lines_lose_their_slack_markup():
    assert overview.plain(":red_circle: *Backup* (core): 3 h old") == "Backup (core): 3 h old"


async def _overview(sessions, check, now, started):
    return (await overview.build(EN, sessions, now, [check], started))[0]


async def test_overview_states(sessions):
    async with sessions() as session, session.begin():
        for host in ("a", "b"):
            session.add(HostReport(host=host, kind="probe", collected_at=NOW, received_at=NOW, data={}))
        session.add(OpsRun(name="probe_job", kind="check", started_at=NOW, finished_at=NOW, status="ok", summary=""))
    started = NOW - timedelta(days=5)

    fresh = await _overview(sessions, Probe(), NOW + timedelta(hours=1), started)
    assert fresh.state == overview.OK and fresh.last_run is not None and fresh.lines == ["Probe: all good"]

    stale = await _overview(sessions, Probe(), NOW + timedelta(hours=27), started)
    assert stale.state == overview.OVERDUE  # no report and no run for more than 26 hours

    just_deployed = await _overview(sessions, Probe(), NOW + timedelta(hours=27), NOW + timedelta(hours=26))
    assert just_deployed.state == overview.OVERDUE  # data exists but is old, so a fresh deploy does not hide it

    warning = await _overview(sessions, Probe(line=":warning: Probe: data missing"), NOW, started)
    assert warning.state == overview.WARN and warning.lines == ["Probe: data missing"]
    problem = await _overview(sessions, Probe(line=":red_circle: Probe: broken"), NOW, started)
    assert problem.state == overview.PROBLEM


async def test_a_check_that_never_ran_is_new_until_its_interval_has_passed(sessions):
    started = NOW - timedelta(hours=2)

    young = await _overview(sessions, Probe(), NOW, started)
    old = await _overview(sessions, Probe(), NOW + timedelta(hours=30), started)

    assert (young.state, young.last_run) == (overview.NEW, None)
    assert old.state == overview.OVERDUE


async def test_a_failed_last_run_is_a_problem_with_its_reason(sessions):
    async with sessions() as session, session.begin():
        session.add(HostReport(host="a", kind="probe", collected_at=NOW, received_at=NOW, data={}))
        session.add(HostReport(host="b", kind="probe", collected_at=NOW, received_at=NOW, data={}))
        session.add(
            OpsRun(
                name="probe_job",
                kind="check",
                started_at=NOW,
                finished_at=NOW,
                status="failed",
                summary="RuntimeError: x",
            )
        )

    row = await _overview(sessions, Probe(), NOW, NOW - timedelta(days=2))

    assert row.state == overview.PROBLEM and row.lines[0] == "The last run failed: RuntimeError: x"


async def _seed(sessions, now):
    async with sessions() as session, session.begin():
        incident = Incident(
            fingerprint="f",
            title="CoreApiDown",
            severity="P1",
            status="open",
            labels={"host": "app-1", "alertname": "CoreApiDown"},
            annotations={"summary": "Core does not answer"},
            started_at=now - timedelta(hours=3),
            last_seen_at=now,
            last_notified_at=now,
            slack_channel="C123",
            slack_ts="1763.001",
        )
        session.add(incident)
        await session.flush()
        session.add(
            IncidentAnalysis(
                incident_id=incident.id,
                requested_by="auto",
                status="done",
                started_at=now - timedelta(hours=2, minutes=59),
                finished_at=now - timedelta(hours=2, minutes=58),
                analysis={"summary": "The pool is exhausted"},
                verified=True,
            )
        )
        session.add(
            OpsRun(
                name="osv_scan",
                kind="check",
                started_at=now - timedelta(hours=1),
                finished_at=now - timedelta(hours=1) + timedelta(seconds=40),
                status="failed",
                summary="Repo not readable",
            )
        )
        session.add(HostReport(host="app-1", kind="trivy", collected_at=now, received_at=now, data={}))
        session.add(HostReport(host="ops-1", kind="trivy", collected_at=now, received_at=now, data={}))


async def test_timeline_merges_all_sources_and_shows_each_collector_run_once(sessions):
    now = datetime.now(UTC)
    await _seed(sessions, now)

    async with sessions() as session:
        result = await timeline.load(EN, session, now)
        collectors = await timeline.load(EN, session, now, kind="collector")
        failed = await timeline.load(EN, session, now, status="failed")
        on_host = await timeline.load(EN, session, now, host="app-1")
        tiny = await timeline.load(EN, session, now, limit=1)

    assert [e.at for e in result.entries] == sorted((e.at for e in result.entries), reverse=True)
    assert {e.kind for e in result.entries} == {"job", "analysis", "incident", "collector"}
    assert {e.title for e in collectors.entries} == {"Reports from app-1: trivy", "Reports from ops-1: trivy"}
    assert {e.title for e in failed.entries} == {"OSV scan of the repos", "Alert P1: CoreApiDown"}
    assert {e.kind for e in on_host.entries} == {"analysis", "incident", "collector"}
    assert tiny.truncated and len(tiny.entries) == 1
    analysis = next(e for e in result.entries if e.kind == "analysis")
    assert analysis.summary == "The pool is exhausted" and analysis.slack.endswith("channel=C123&message_ts=1763.001")


async def test_timeline_period_cuts_old_entries(sessions):
    now = datetime.now(UTC)
    await _seed(sessions, now - timedelta(days=3))

    async with sessions() as session:
        day = await timeline.load(EN, session, now, period="24h")
        week = await timeline.load(EN, session, now, period="7d")

    assert day.entries == [] and len(week.entries) == 5


@pytest.fixture
def client(database_url, sessions):
    settings = Settings(
        database_url=database_url, base_url="http://ops.test", oncall_people=[ALICE, BOB], timezone="Europe/Vienna"
    )
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        yield client


def test_pages_are_empty_but_work_on_a_fresh_install(client):
    assert "No entries in the chosen period." in client.get("/ops").text
    assert "No entries in the chosen period." in client.get("/ops/history").text
    assert client.get("/ops/runs/999999").status_code == 404


async def test_overview_and_history_pages_show_runs_analyses_and_filters(client, sessions):
    now = datetime.now(UTC)
    await _seed(sessions, now)

    page = client.get("/ops").text
    assert "Checks" in page and "OSV scan of the repos" in page and "AI analysis" in page
    history = client.get("/ops/history").text
    assert "The pool is exhausted" in history and "Slack thread" in history and "Repo not readable" in history
    assert "Reports from app-1: trivy" in history
    assert "Reports from app-1: trivy" in client.get("/ops/history?kind=collector&host=app-1").text
    assert "Reports from ops-1: trivy" not in client.get("/ops/history?kind=collector&host=app-1").text
    assert "Repo not readable" not in client.get("/ops/history?status=ok").text
    assert client.get("/ops/history?period=bogus").status_code == 200  # an unknown period falls back to the default


async def test_run_detail_shows_result_and_links_the_incident_of_a_failed_job(client, sessions):
    now = datetime.now(UTC)
    async with sessions() as session, session.begin():
        session.add(
            OpsRun(
                name="<script>x</script>",
                kind="check",
                started_at=now,
                finished_at=now,
                status="failed",
                summary="<b>broken</b>",
            )
        )
        session.add(
            Incident(
                fingerprint="g",
                title="ScheduledJobFailed",
                severity="P2",
                status="open",
                labels={"alertname": "ScheduledJobFailed", "job": "<script>x</script>"},
                annotations={},
                started_at=now,
                last_seen_at=now,
                last_notified_at=now,
            )
        )

    async with sessions() as session:  # the digest of the app start has a row of its own
        run_id = await session.scalar(select(OpsRun.id).where(OpsRun.name == "<script>x</script>"))
        incident_id = await session.scalar(select(Incident.id))
    page = client.get(f"/ops/runs/{run_id}").text

    assert "<script>x</script>" not in page and "&lt;b&gt;broken&lt;/b&gt;" in page
    assert f'href="/incidents/{incident_id}"' in page


async def test_the_overview_lists_false_alarm_candidates_with_a_suggestion(client, sessions):
    now = datetime.now(UTC)
    async with sessions() as session, session.begin():
        for hours in (50, 30, 10):  # three short alarms nobody touched
            started = now - timedelta(hours=hours)
            session.add(
                Incident(
                    fingerprint=f"f{hours}",
                    title="<b>DiskBlip</b>",
                    severity="P2",
                    status="resolved",
                    labels={"alertname": "<b>DiskBlip</b>"},
                    annotations={},
                    started_at=started,
                    resolved_at=started + timedelta(minutes=3),
                    last_seen_at=started,
                    last_notified_at=started,
                )
            )

    page = client.get("/ops").text

    assert "False-alarm candidates" in page and "&lt;b&gt;DiskBlip&lt;/b&gt;" in page and "(3x)" in page
    assert "<b>DiskBlip</b>" not in page and "at least 5 min" in page


async def test_the_overview_says_so_when_there_are_no_false_alarm_candidates(client):
    assert "None in the last 7 days." in client.get("/ops").text


async def test_the_strip_marks_failed_missing_and_good_days(sessions):
    day = timedelta(days=1)
    async with sessions() as session, session.begin():
        for back in (0, 1, 3):  # both hosts reported on these days
            for host in ("a", "b"):
                moment = NOW - back * day
                session.add(HostReport(host=host, kind="probe", collected_at=moment, received_at=moment, data={}))
        session.add(OpsRun(name="probe_job", kind="check", started_at=NOW - day, finished_at=NOW, status="failed"))
        session.add(OpsRun(name="probe_job", kind="check", started_at=NOW, finished_at=NOW, status="ok"))
        session.add(OpsRun(name="probe_job", kind="check", started_at=NOW - 3 * day, finished_at=NOW, status="ok"))
        session.add(OpsRun(name="probe_job", kind="check", started_at=NOW - 4 * day, finished_at=NOW, status="ok"))

    row = await _overview(sessions, Probe(), NOW, NOW - timedelta(days=20))

    cells = dict(row.strip)
    assert len(row.strip) == overview.STRIP_DAYS
    today = row.strip[-1][0]
    assert cells[today] == overview.STRIP_OK
    assert cells[today - day] == overview.STRIP_FAILED  # a failed job beats arrived reports
    assert cells[today - 2 * day] == overview.STRIP_NONE
    assert cells[today - 3 * day] == overview.STRIP_OK
    assert cells[today - 4 * day] == overview.STRIP_PARTIAL  # the job ran but no host reported


def test_headline_and_rest_split_the_report_lines():
    row = overview.CheckRow("x", overview.OK, None, "daily", ["First line", "• second", "• third"], [])

    assert row.headline == "First line"
    assert row.rest == ["second", "third"]


def test_the_hero_names_what_needs_a_look():
    from app.web import activity

    assert activity._hero(EN, [], 3)[:2] == ("ok", "All in order.")
    one = [activity.Attention("warn", "A", "", "#check-0")]
    assert activity._hero(EN, one, 3)[:2] == ("warn", "One thing needs a look.")
    two = [*one, activity.Attention("problem", "B", "", "#check-1")]
    assert activity._hero(EN, two, 3)[:2] == ("problem", "2 things need you now.")


def test_checks_are_grouped_in_report_order_and_unknown_ones_go_last():
    from app.web import activity

    def row(group):
        return overview.CheckRow("x", overview.OK, None, "", [], [], group=group)

    groups = activity._grouped(EN, [row("backup"), row("other"), row("vulns"), row("unknown")])

    assert [title for title, _ in groups] == ["Vulnerabilities", "Backup", "Other"]
    assert [i for i, _ in groups[-1][1]] == [1, 3]


async def test_history_groups_by_day_and_keeps_filters_in_chip_links(client, sessions):
    now = datetime.now(UTC)
    await _seed(sessions, now)

    page = client.get("/ops/history?kind=job&period=30d").text

    assert "Today" in page
    assert 'href="/ops/history?kind=job"' in page  # the period chip "7 days" drops back to the default
    assert 'href="/ops/history?period=30d"' in page  # "Alle" in the kind row keeps the period


async def test_the_reports_of_one_collector_run_are_one_entry_and_a_broken_report_warns(sessions):
    now = datetime.now(UTC)
    async with sessions() as session, session.begin():
        for kind, minutes, data in [
            ("patches", 100, {}),
            ("trivy", 98, {}),
            ("images", 95, {"error": "docker unreachable"}),
            ("patches", 700, {}),  # the next night: a gap of more than 10 minutes starts a new run
        ]:
            at = now - timedelta(minutes=minutes)
            session.add(HostReport(host="app-1", kind=kind, collected_at=at, received_at=at, data=data))
        session.add(HostReport(host="ops-1", kind="patches", collected_at=now, received_at=now, data={}))

    async with sessions() as session:
        entries = (await timeline.load(EN, session, now, kind="collector")).entries

    assert [(e.host, e.title, e.status) for e in entries] == [
        ("ops-1", "Reports from ops-1: patches", timeline.OK),
        ("app-1", "Reports from app-1: images, patches, trivy", timeline.WARN),
        ("app-1", "Reports from app-1: patches", timeline.OK),
    ]
    assert entries[1].summary == "images: docker unreachable"


async def test_a_long_series_of_reports_is_not_chained_into_one_run_and_errors_are_masked(sessions):
    now = datetime.now(UTC)
    async with sessions() as session, session.begin():
        for minutes in (0, 25, 50, 75):  # each within 40 minutes of the next, but not of the first
            at = now - timedelta(minutes=minutes)
            error = {"error": "git clone https://user:hunter2secret@bitbucket.org/x failed, anna@example.com"}
            session.add(HostReport(host="app-1", kind="patches", collected_at=at, received_at=at, data=error))
        session.add(HostReport(host="ops-1", kind="patches", collected_at=now, received_at=now, data={}))

    async with sessions() as session:
        entries = (await timeline.load(EN, session, now, kind="collector", host="app-1")).entries

    assert len(entries) == 2 and all(e.host == "app-1" for e in entries)
    assert "anna@example.com" not in entries[0].summary and "hunter2secret" not in entries[0].summary


def test_every_check_has_a_help_text_with_a_ticket():
    helps = all_help(EN)

    assert set(helps) == set(CHECK_KEYS)
    for item in helps.values():
        assert item.what and item.why and item.ours
        assert all(link.url.startswith("https://") for link in item.links)


def test_the_overview_and_the_help_page_explain_the_checks(client):
    help_page = client.get("/ops/help")

    assert help_page.status_code == 200
    assert "Why we use it:" in help_page.text and "https://trivy.dev/" in help_page.text
    assert 'id="TrivyCheck"' in help_page.text
    assert 'href="/ops/help"' in client.get("/ops").text
