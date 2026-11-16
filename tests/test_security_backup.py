from datetime import datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr

from app.security.backup import BackupCheck, BackupError, CoolifyBackups, Database, Run
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import EN
from tests.security_helpers import open_incidents

DB = "a1b2c3d4e5f6g7h8i9j0k1l2"


def run(age: timedelta, now: datetime, size: int = 2668, status: str = "success", s3: bool = True) -> Run:
    return Run(status=status, size=size, created_at=now - age, s3_uploaded=s3)


class FakeSource:
    def __init__(self):
        self.result: Database | Exception = BackupError("not set")
        self.calls = 0

    async def database(self, uuid):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def source():
    return FakeSource()


@pytest.fixture
def security(sessions, service, clock, source):
    signals = Signals(sessions, service, clock)
    check = BackupCheck(sessions, signals, clock, source, [DB], link="http://coolify.test", locale=EN)
    return SecurityService(sessions, signals, clock, [check], locale=EN), check


def db(*runs: Run, schedules=("0 3 * * *",)) -> Database:
    return Database(uuid=DB, name="app-db", schedules=list(schedules), runs=list(runs))


async def test_no_successful_backup_for_26_hours_opens_a_p1_with_the_link(security, source, sessions, clock, pager):
    _, check = security
    source.result = db(run(timedelta(hours=27), clock.now))

    await check.periodic(clock.now)

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity, incident.labels["database"]) == ("BackupTooOld", "P1", DB)
    assert "The last successful backup of app-db is 27 h old" in incident.annotations["summary"]
    assert incident.annotations["link"] == "http://coolify.test"
    assert len(pager.pages) == 1


async def test_a_new_backup_resolves_it(security, source, sessions, clock):
    _, check = security
    source.result = db(run(timedelta(hours=27), clock.now))
    await check.periodic(clock.now)

    clock.advance(timedelta(hours=1))
    source.result = db(run(timedelta(minutes=5), clock.now), run(timedelta(hours=28), clock.now))
    await check.periodic(clock.now)

    assert await open_incidents(sessions) == []


@pytest.mark.parametrize(
    ("runs", "schedules", "expected"),
    [
        (lambda now: [], (), {("BackupTooOld", "P1")}),  # no schedule at all
        (
            lambda now: [run(timedelta(hours=1), now, status="failed")],
            ("0 3 * * *",),
            {("BackupTooOld", "P1"), ("BackupFailed", "P2")},
        ),
        (
            lambda now: [run(timedelta(hours=1), now, size=1000), run(timedelta(hours=25), now, size=5000)],
            ("0 3 * * *",),
            {("BackupShrunk", "P2")},
        ),
        (lambda now: [run(timedelta(hours=1), now, s3=False)], ("0 3 * * *",), {("BackupNotInS3", "P2")}),
        (lambda now: [run(timedelta(hours=1), now), run(timedelta(hours=25), now)], ("0 3 * * *",), set()),
    ],
    ids=["no-schedule", "failed-run", "shrunk", "not-in-s3", "all-good"],
)
async def test_verdicts(security, source, sessions, clock, runs, schedules, expected):
    _, check = security
    source.result = db(*runs(clock.now), schedules=schedules)

    await check.periodic(clock.now)

    assert {(i.title, i.severity) for i in await open_incidents(sessions)} == expected


async def test_an_unreadable_api_reports_itself_and_keeps_the_last_verdict(security, source, sessions, clock):
    _, check = security
    source.result = db(run(timedelta(hours=30), clock.now))
    await check.periodic(clock.now)

    clock.advance(timedelta(minutes=31))
    source.result = BackupError("Coolify API databases/x: 401")
    await check.periodic(clock.now)

    assert {i.title for i in await open_incidents(sessions)} == {"BackupTooOld", "BackupCheckFailed"}


async def test_the_api_is_asked_every_30_minutes_only(security, source, clock):
    _, check = security
    source.result = db(run(timedelta(hours=1), clock.now))

    await check.periodic(clock.now)
    clock.advance(timedelta(minutes=10))
    await check.periodic(clock.now)
    clock.advance(timedelta(minutes=21))
    await check.periodic(clock.now)

    assert source.calls == 2


async def test_daily_lines_show_size_age_and_s3(security, source, clock):
    service, check = security
    assert "the check has not run for over 2 hours" in (await service.daily_lines(clock.now))[0]

    source.result = db(run(timedelta(hours=5), clock.now, size=3 * 1024))
    await check.periodic(clock.now)
    [line] = await service.daily_lines(clock.now + timedelta(minutes=30))

    assert line.startswith("Backup (app-db): 3.0 KB, 5 h old (")
    assert line.endswith(", in S3)")


async def test_without_token_or_databases_the_digest_says_that_nothing_is_checked(sessions, service, clock):
    signals = Signals(sessions, service, clock)
    security = SecurityService(
        sessions, signals, clock, [BackupCheck(sessions, signals, clock, None, [DB], locale=EN)], locale=EN
    )

    [line] = await security.daily_lines(clock.now)
    assert "backups are not checked" in line


async def test_the_coolify_adapter_reads_enabled_schedules_and_their_runs():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer tok"
        if request.url.path == f"/api/v1/databases/{DB}":
            return httpx.Response(200, json={"uuid": DB, "name": "app-db"})
        executions = [
            {"status": "success", "size": 2668, "created_at": "2026-11-14T03:00:02.000000Z", "s3_uploaded": True},
            {"status": "success", "size": 2670, "created_at": "2026-11-13T03:00:05.000000Z", "s3_uploaded": True},
        ]
        return httpx.Response(
            200,
            json=[
                {"frequency": "0 3 * * *", "enabled": True, "executions": executions},
                {
                    "frequency": "0 * * * *",
                    "enabled": False,
                    "executions": [{"status": "failed", "created_at": "2026-11-14T04:00:00Z"}],
                },
            ],
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await CoolifyBackups(client, "http://coolify.test/", SecretStr("tok"), EN).database(DB)

    assert (result.name, result.schedules) == ("app-db", ["0 3 * * *"])
    assert [r.size for r in result.runs] == [2668, 2670]


async def test_the_coolify_adapter_turns_http_errors_into_backup_errors():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401))) as client:
        with pytest.raises(BackupError, match="401"):
            await CoolifyBackups(client, "http://coolify.test", SecretStr("tok"), EN).database(DB)
