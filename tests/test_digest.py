import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.incidents.digest import build_digest
from app.incidents.schemas import AlertIn
from app.jobs import Jobs
from tests.fakes import EN, Clock


def alert(name: str, severity: str = "P2", ends=None) -> AlertIn:
    return AlertIn(labels={"alertname": name, "severity": severity}, endsAt=ends)


async def test_empty_digest(sessions, clock):
    assert "No alerts in the last 24 hours" in await build_digest(EN, sessions, clock.now, "http://ops.test")


async def test_digest_lists_open_and_recently_resolved(service, sessions, clock):
    await service.handle_alerts([alert("StillBroken", "P1"), alert("Fixed")])
    clock.advance(timedelta(minutes=30))
    await service.handle_alerts([alert("Fixed", ends=clock.now)])
    clock.advance(timedelta(hours=1))

    text = await build_digest(EN, sessions, clock.now, "http://ops.test/")

    assert "*Open (1)*" in text
    assert "P1 <http://ops.test/incidents/1|StillBroken>, for 90 min" in text
    assert "*Resolved in the last 24 h (1)*" in text
    assert "P2 Fixed, took 30 min" in text


async def test_resolved_long_ago_is_not_in_the_digest(service, sessions, clock):
    await service.handle_alerts([alert("Old")])
    await service.handle_alerts([alert("Old", ends=clock.now)])
    clock.advance(timedelta(hours=25))

    assert "No alerts in the last 24 hours" in await build_digest(EN, sessions, clock.now, "http://ops.test")


async def jobs_at(service, chat, sessions, moment: datetime) -> tuple[Jobs, Clock]:
    clock = Clock(moment)
    client = httpx.AsyncClient()
    return Jobs(service, chat, sessions, clock, "http://ops.test", None, client, locale=EN), clock


async def test_digest_is_posted_once_per_day_after_eight_vienna(service, chat, sessions):
    # 05:59 UTC is 07:59 in Vienna (summer time), 06:00 UTC is 08:00.
    jobs, clock = await jobs_at(service, chat, sessions, datetime(2026, 10, 20, 5, 59, tzinfo=UTC))
    assert not await jobs.run_digest_if_due()

    clock.now = datetime(2026, 10, 20, 6, 0, tzinfo=UTC)
    assert await jobs.run_digest_if_due()
    assert not await jobs.run_digest_if_due()
    assert len(chat.ops) == 1

    clock.now = datetime(2026, 10, 21, 6, 1, tzinfo=UTC)
    assert await jobs.run_digest_if_due()
    assert len(chat.ops) == 2


async def test_a_restart_in_the_afternoon_catches_up_on_the_missed_digest(service, chat, sessions):
    jobs, _ = await jobs_at(service, chat, sessions, datetime(2026, 10, 20, 14, 0, tzinfo=UTC))

    assert await jobs.run_digest_if_due()


async def test_heartbeat_pings_the_configured_url(service, chat, sessions, clock):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    jobs = Jobs(service, chat, sessions, clock, "http://ops.test", "https://hc-ping.com/abc", client, locale=EN)
    await jobs.ping()
    await client.aclose()

    assert seen == ["https://hc-ping.com/abc"]


@pytest.mark.parametrize("status", [404, 302])
async def test_a_failed_heartbeat_does_not_put_the_ping_url_into_the_log(service, chat, sessions, caplog, status):
    url = "https://monitor.example/api/push/secret-token-123"
    headers = {"location": url + "?moved=1"} if status == 302 else {}
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(status, headers=headers)))
    clock = Clock(datetime(2026, 10, 19, 10, 0, tzinfo=UTC))
    jobs = Jobs(service, chat, sessions, clock, "http://ops.test", url, client, locale=EN)
    caplog.set_level(logging.WARNING, logger="httpx")  # what the lifespan of the app does (test_alerts_auth)
    with caplog.at_level(logging.DEBUG):
        try:
            await jobs.ping()
        except RuntimeError as error:
            assert str(status) in str(error)
            # What the job loop does: the message and the whole traceback chain end up in the log.
            logging.getLogger("app.jobs").exception("job %s failed", "heartbeat")
        else:
            raise AssertionError("a failed ping has to raise")
    await client.aclose()
    assert "secret-token-123" not in caplog.text


async def test_the_tick_runs_the_analysis_step_and_an_error_in_it_does_not_stop_the_incident_step(
    service, chat, sessions
):
    class Analysis:
        ticks = 0

        async def tick(self):
            self.ticks += 1
            raise RuntimeError("boom")

    analysis = Analysis()
    jobs = Jobs(
        service,
        chat,
        sessions,
        Clock(datetime(2026, 10, 19, 10, 0, tzinfo=UTC)),
        "http://ops.test",
        None,
        httpx.AsyncClient(),
        locale=EN,
        analysis=analysis,
    )
    await jobs.tick()
    assert analysis.ticks == 1
