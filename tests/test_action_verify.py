from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.actions.reboots import RebootJobs
from app.actions.service import VERIFY_GRACE, ActionService
from app.actions.verify import SETTLE, ActionVerifier, HttpHealth
from app.models import ActionJob, RebootRequest
from app.security.reboot import RebootQuestions
from app.security.signals import Signals
from runner.catalog import load_catalog
from tests.fakes import EN, START

HOST = "app-1"
URLS = {HOST: ["https://api.test/health", "https://admin.test/health"]}
KEY = Ed25519PrivateKey.generate()


class FakeHealth:
    def __init__(self) -> None:
        self.red: list[str] = []
        self.asked: list[list[str]] = []

    async def failures(self, urls: list[str]) -> list[str]:
        self.asked.append(urls)
        return list(self.red)


@pytest.fixture
def jobs(sessions, clock) -> ActionService:
    return ActionService(sessions, clock, load_catalog(), KEY, {HOST}, locale=EN)


@pytest.fixture
def health() -> FakeHealth:
    return FakeHealth()


@pytest.fixture
def verifier(sessions, clock, service, jobs, health):
    return ActionVerifier(sessions, jobs, Signals(sessions, service, clock), health, URLS, clock, locale=EN)


async def run_job(
    jobs: ActionService, runbook: str = "image_prune", params=None, status: str = "succeeded"
) -> ActionJob:
    job = await jobs.propose(runbook, params or {}, HOST, "U")
    await jobs.approve(job.action_id, "U")
    await jobs.claim(HOST)
    await jobs.started(HOST, job.action_id)
    return await jobs.finished(HOST, job.action_id, status, "done")


async def state(sessions, job_id: int) -> tuple[str | None, str]:
    async with sessions() as session:
        row = await session.get(ActionJob, job_id)
        return row.verify_status, row.verify_detail


async def test_a_finished_action_is_checked_and_a_green_check_closes_it(
    jobs, verifier, health, sessions, chat, clock
) -> None:
    job = await run_job(jobs)
    assert (await state(sessions, job.id))[0] == "pending"
    await verifier.tick()
    assert (await state(sessions, job.id))[
        0
    ] == "pending" and health.asked == []  # too soon: the old app may still answer
    clock.advance(SETTLE)
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "ok"
    assert health.asked == [URLS[HOST]] and chat.posted == []
    events = [a.event for a in await jobs.audit_log(job.id)]
    assert events[-1] == "verify_ok"


async def test_a_failed_action_is_checked_too(jobs, verifier, sessions, clock) -> None:
    job = await run_job(jobs, status="failed")
    clock.advance(SETTLE)
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "ok"


async def test_a_rejected_job_is_not_checked(jobs, sessions) -> None:
    job = await jobs.propose("image_prune", {}, HOST, "U")
    await jobs.approve(job.action_id, "U")
    await jobs.claim(HOST)
    await jobs.finished(HOST, job.action_id, "rejected", "signature")
    assert (await state(sessions, job.id))[0] is None


async def test_red_inside_the_grace_period_waits_then_opens_a_p1_with_the_rollback_hint(
    jobs, verifier, health, sessions, clock, chat, pager
) -> None:
    job = await run_job(jobs)
    health.red = ["https://api.test/health: 503"]
    clock.advance(SETTLE)
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "pending" and chat.posted == []

    clock.advance(VERIFY_GRACE["health"])
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "red"
    [view] = chat.posted
    assert (view.title, view.severity) == ("ActionHealthRed", "P1")
    assert "image_prune" in view.summary and "503" in view.summary and "Rollback:" in view.summary
    assert pager.pages

    await verifier.tick()  # still red: the same incident
    assert len(chat.posted) == 1


async def test_the_p1_closes_when_the_urls_answer_again(jobs, verifier, health, sessions, clock, chat) -> None:
    job = await run_job(jobs)
    health.red = ["https://api.test/health: 503"]
    clock.advance(VERIFY_GRACE["health"])
    await verifier.tick()
    health.red = []
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "recovered"
    assert chat.updates[-1].status == "resolved"


async def test_a_reboot_gets_a_longer_grace_period(jobs, verifier, health, sessions, clock, chat) -> None:
    async with sessions() as session, session.begin():
        session.add(RebootRequest(host=HOST, requested_at=START, status="approved", token="x"))  # noqa: S106
    job = await jobs.propose(
        "reboot_scheduled", {"reboot_request": 1}, HOST, "system", approved_by="U", reboot_request_id=1
    )
    await jobs.claim(HOST)
    await jobs.started(HOST, job.action_id)
    await jobs.finished(HOST, job.action_id, "succeeded", "the server restarted")
    health.red = ["x: 502"]
    clock.advance(VERIFY_GRACE["health"] + timedelta(seconds=1))
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "pending" and chat.posted == []
    clock.advance(VERIFY_GRACE["reboot"])
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "red"


async def test_a_server_without_health_urls_is_not_checked_and_says_so(sessions, clock, service, jobs, health) -> None:
    bare = ActionVerifier(sessions, jobs, Signals(sessions, service, clock), health, {}, clock, locale=EN)
    job = await run_job(jobs)
    clock.advance(SETTLE)
    await bare.tick()
    status, detail = await state(sessions, job.id)
    assert status == "skipped" and "no health URLs" in detail


async def test_the_failure_text_is_masked(jobs, verifier, health, sessions, clock) -> None:
    job = await run_job(jobs)
    health.red = ["https://x/health?user=anna@example.com: 500"]
    clock.advance(SETTLE)
    await verifier.tick()
    assert "anna@example.com" not in (await state(sessions, job.id))[1]


async def test_a_lost_job_is_checked_too(jobs, verifier, sessions, clock) -> None:
    job = await jobs.propose("image_prune", {}, HOST, "U")
    await jobs.approve(job.action_id, "U")
    await jobs.claim(HOST)
    await jobs.started(HOST, job.action_id)
    clock.advance(timedelta(minutes=46))
    await jobs.expire()
    assert (await state(sessions, job.id))[0] == "pending"


# --- reboot jobs from approvals -------------------------------------------------------------------------------------


@pytest.fixture
def reboots(sessions, chat, clock) -> RebootQuestions:
    return RebootQuestions(sessions, chat, clock, self_rebooting=[], locale=EN)


async def approve_reboot(sessions, scheduled_for, approved_by="U_ALICE") -> int:
    async with sessions() as session, session.begin():
        row = RebootRequest(
            host=HOST,
            requested_at=START,
            status="approved",
            token="t",  # noqa: S106
            approved_by=approved_by,
            approved_at=START,
            scheduled_for=scheduled_for,
        )
        session.add(row)
        await session.flush()
        return row.id


async def all_jobs(sessions) -> list[ActionJob]:
    async with sessions() as session:
        return list((await session.scalars(select(ActionJob))).all())


async def test_an_approved_reboot_becomes_one_approved_job_when_its_time_has_come(
    sessions, jobs, reboots, clock
) -> None:
    request_id = await approve_reboot(sessions, START + timedelta(hours=10))
    steps = RebootJobs(reboots, jobs, clock)
    await steps.tick()
    assert await all_jobs(sessions) == []  # not yet its time

    clock.advance(timedelta(hours=10))
    await steps.tick()
    await steps.tick()  # a second tick makes no second job
    [job] = await all_jobs(sessions)
    assert (job.runbook, job.params, job.status, job.approved_by) == (
        "reboot_scheduled",
        {"reboot_request": request_id},
        "approved",
        "U_ALICE",
    )
    assert job.reboot_request_id == request_id


async def test_the_reboot_job_marks_the_request_done_and_is_executed_once(sessions, jobs, reboots, clock) -> None:
    request_id = await approve_reboot(sessions, START)
    await RebootJobs(reboots, jobs, clock).tick()
    envelope = await jobs.claim(HOST)
    assert envelope["job"]["runbook"] == "reboot_scheduled"
    await jobs.started(HOST, envelope["job"]["action_id"])
    await jobs.finished(HOST, envelope["job"]["action_id"], "succeeded", "the server restarted")
    async with sessions() as session:
        request = await session.get(RebootRequest, request_id)
    assert (request.status, request.done_at) == ("done", clock())
    await RebootJobs(reboots, jobs, clock).tick()
    assert len(await all_jobs(sessions)) == 1  # a done request is not approved any more


async def test_a_server_without_a_runner_gets_no_reboot_job(sessions, jobs, reboots, clock) -> None:
    async with sessions() as session, session.begin():
        session.add(
            RebootRequest(
                host="app-2",
                requested_at=START,
                status="approved",
                token="t",  # noqa: S106
                approved_by="U",
                approved_at=START,
                scheduled_for=START,
            )
        )
    await RebootJobs(reboots, jobs, clock).tick()
    assert await all_jobs(sessions) == []


async def test_the_http_health_check_counts_only_2xx_as_green() -> None:
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return {"/ok": httpx.Response(200), "/redirect": httpx.Response(302), "/down": httpx.Response(503)}[
            request.url.path
        ]

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        found = await HttpHealth(client).failures(["http://h/ok", "http://h/redirect", "http://h/down"])
    assert found == ["http://h/redirect: 302", "http://h/down: 503"]


async def test_an_open_p1_closes_when_the_servers_urls_are_removed(
    jobs, verifier, health, sessions, clock, chat, service
) -> None:
    job = await run_job(jobs)
    health.red = ["x: 500"]
    clock.advance(VERIFY_GRACE["health"])
    await verifier.tick()
    assert (await state(sessions, job.id))[0] == "red"
    bare = ActionVerifier(sessions, jobs, Signals(sessions, service, clock), health, {}, clock, locale=EN)
    await bare.tick()
    assert (await state(sessions, job.id))[0] == "skipped" and chat.updates[-1].status == "resolved"


async def test_a_reboot_request_with_a_job_does_not_try_again_every_tick(
    sessions, jobs, reboots, clock, monkeypatch
) -> None:
    await approve_reboot(sessions, START)
    steps = RebootJobs(reboots, jobs, clock)
    await steps.tick()
    calls = []
    original = jobs.propose
    monkeypatch.setattr(jobs, "propose", lambda *a, **k: calls.append(1) or original(*a, **k))
    await steps.tick()
    assert calls == []
