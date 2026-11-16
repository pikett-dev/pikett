from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.actions.service import ActionService
from app.actions.watch import SILENT_AFTER, RunnerWatch
from app.security.signals import Signals
from runner.catalog import load_catalog
from tests.fakes import EN

HOST = "app-1"
KEY = Ed25519PrivateKey.generate()


def build(sessions, clock, service, hosts=None):
    jobs = ActionService(sessions, clock, load_catalog(), KEY, {HOST}, locale=EN)
    return jobs, RunnerWatch(
        sessions, Signals(sessions, service, clock), clock, {HOST} if hosts is None else hosts, locale=EN
    )


async def test_a_silent_runner_opens_a_p1_and_recovery_closes_it(sessions, clock, service, chat, pager) -> None:
    jobs, watch = build(sessions, clock, service)
    await jobs.heartbeat(HOST, "0.1", "abc")
    await watch.check()
    assert chat.posted == []  # fresh

    clock.advance(SILENT_AFTER + timedelta(seconds=1))
    await watch.check()
    assert [(v.title, v.severity) for v in chat.posted] == [("RunnerSilent", "P1")]
    assert "app-1" in chat.posted[0].summary and "3 minutes" in chat.posted[0].summary
    assert pager.pages  # a P1 pages the person on call

    await watch.check()  # still silent: the same incident, no second alert
    assert len(chat.posted) == 1

    await jobs.heartbeat(HOST, "0.1", "abc")
    await watch.check()
    assert chat.updates and chat.updates[-1].status == "resolved"


async def test_a_server_whose_runner_never_polled_raises_nothing(sessions, clock, service, chat) -> None:
    _, watch = build(sessions, clock, service)
    clock.advance(timedelta(hours=1))
    await watch.check()
    assert chat.posted == []


async def test_after_a_restart_of_the_service_the_time_counts_from_the_restart(sessions, clock, service, chat) -> None:
    jobs, _ = build(sessions, clock, service)
    await jobs.heartbeat(HOST, "0.1", "abc")
    clock.advance(timedelta(hours=2))  # the service was down; nothing could poll
    _, restarted = build(sessions, clock, service)
    await restarted.check()
    assert chat.posted == []
    clock.advance(SILENT_AFTER + timedelta(seconds=1))
    await restarted.check()
    assert [v.title for v in chat.posted] == ["RunnerSilent"]


async def test_a_server_that_is_no_longer_configured_is_not_watched(sessions, clock, service, chat) -> None:
    jobs, _ = build(sessions, clock, service)
    await jobs.heartbeat("retired-host", "0.1", "abc")
    clock.advance(timedelta(hours=1))
    _, watch = build(sessions, clock, service)
    await watch.check()
    assert chat.posted == []


async def test_removing_a_server_closes_its_open_alert(sessions, clock, service, chat) -> None:
    jobs, watch = build(sessions, clock, service)
    await jobs.heartbeat(HOST, "0.1", "abc")
    clock.advance(SILENT_AFTER + timedelta(seconds=1))
    await watch.check()
    assert [v.title for v in chat.posted] == ["RunnerSilent"]
    _, dropped = build(sessions, clock, service, hosts=set())  # HOST left RUNNER_TOKENS
    await dropped.check()
    assert chat.updates[-1].status == "resolved"


async def test_a_server_with_a_job_in_flight_is_not_silent(sessions, clock, service, chat) -> None:
    jobs, watch = build(sessions, clock, service)
    job = await jobs.propose("image_prune", {}, HOST, "U")
    await jobs.approve(job.action_id, "U")
    await jobs.heartbeat(HOST, "0.1", "abc")
    await jobs.claim(HOST)  # the runner takes the job and stops polling while it works
    clock.advance(timedelta(minutes=10))
    await watch.check()
    assert chat.posted == []
