import asyncio
import base64
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.actions.service import VALID_FOR, ActionError, ActionService
from app.config import Settings
from app.main import create_app
from app.models import ActionJob, RebootRequest, RunnerHeartbeat
from runner.catalog import CATALOG_PATH, load_catalog, parse_catalog
from runner.jobs import verify_job
from tests.fakes import EN, START, Clock, FakeChat, FakePager

KEY = Ed25519PrivateKey.generate()
TEST, OPS = "app-1", "ops-server"
USER = "U_ALICE"
TOK_TEST, TOK_OPS = "t" * 40, "o" * 40


@pytest.fixture
def jobs(sessions, clock) -> ActionService:
    return ActionService(sessions, clock, load_catalog(), KEY, {TEST, OPS}, locale=EN)


async def events(jobs: ActionService, job_id: int) -> list[str]:
    return [row.event for row in await jobs.audit_log(job_id)]


async def approved(jobs: ActionService, **kwargs) -> ActionJob:
    job = await jobs.propose("image_prune", {}, TEST, USER, **kwargs)
    assert await jobs.approve(job.action_id, USER) is None
    return job


async def test_the_life_of_a_job_is_in_the_audit_log(jobs, sessions, clock) -> None:
    job = await jobs.propose("image_prune", {}, TEST, USER)
    assert job.status == "proposed"
    assert await jobs.approve(job.action_id, "U_BOB") is None
    envelope = await jobs.claim(TEST)
    assert envelope is not None and envelope["job"]["action_id"] == job.action_id
    await jobs.started(TEST, job.action_id)
    done = await jobs.finished(TEST, job.action_id, "succeeded", "3 images removed")

    assert (done.status, done.approved_by, done.summary) == ("succeeded", "U_BOB", "3 images removed")
    assert await events(jobs, job.id) == ["created", "approved", "delivered", "started", "succeeded"]


async def test_the_delivered_job_verifies_with_the_public_key(jobs, clock) -> None:
    job = await approved(jobs)
    envelope = await jobs.claim(TEST)
    verified = verify_job(envelope, public_key=KEY.public_key(), catalog=load_catalog(), host=TEST, now=clock())
    assert verified.action_id == job.action_id
    assert verified.expires_at - clock() == VALID_FOR


async def test_a_job_not_approved_is_never_delivered(jobs) -> None:
    await jobs.propose("image_prune", {}, TEST, USER)
    assert await jobs.claim(TEST) is None


async def test_an_expired_job_is_never_delivered_even_before_the_sweep(jobs, clock) -> None:
    await approved(jobs)
    clock.advance(VALID_FOR)
    assert await jobs.claim(TEST) is None


async def test_the_sweep_expires_what_was_not_delivered_in_time_and_logs_it(jobs, sessions, clock) -> None:
    proposed = await jobs.propose("image_prune", {}, TEST, USER)
    waiting = await approved(jobs)
    clock.advance(VALID_FOR + timedelta(seconds=1))
    assert await jobs.expire() == 2
    assert await jobs.expire() == 0
    assert await events(jobs, proposed.id) == ["created", "expired"]
    assert (await events(jobs, waiting.id))[-1] == "expired"
    assert await jobs.approve(proposed.action_id, USER) == "This action is already approved or finished."


async def test_an_approval_after_the_expiry_is_refused(jobs, sessions, clock) -> None:
    job = await jobs.propose("image_prune", {}, TEST, USER)
    clock.advance(VALID_FOR)
    assert await jobs.approve(job.action_id, USER) == "The approval has expired."
    assert await jobs.claim(TEST) is None
    assert await events(jobs, job.id) == ["created", "expired"]


async def test_a_second_approval_changes_nothing(jobs, sessions) -> None:
    job = await approved(jobs)
    assert await jobs.approve(job.action_id, "U_BOB") == "This action is already approved or finished."
    assert await events(jobs, job.id) == ["created", "approved"]
    assert await jobs.approve("unknown", USER) == "Unknown approval."


async def test_two_runners_polling_at_once_get_the_job_once(jobs) -> None:
    await approved(jobs)
    results = await asyncio.gather(*(jobs.claim(TEST) for _ in range(8)))
    assert sum(r is not None for r in results) == 1


async def test_jobs_are_delivered_in_order_to_their_own_server_only(jobs) -> None:
    other = await jobs.propose("image_prune", {}, OPS, USER)
    await jobs.approve(other.action_id, USER)
    first = await approved(jobs)
    second = await approved(jobs)
    assert (await jobs.claim(TEST))["job"]["action_id"] == first.action_id
    await jobs.started(TEST, first.action_id)
    await jobs.finished(TEST, first.action_id, "succeeded", "")
    assert (await jobs.claim(TEST))["job"]["action_id"] == second.action_id
    assert (await jobs.claim(OPS))["job"]["action_id"] == other.action_id


async def test_a_runner_cannot_touch_the_job_of_another_server(jobs) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    with pytest.raises(ActionError, match="unknown job"):
        await jobs.started(OPS, job.action_id)
    with pytest.raises(ActionError, match="unknown job"):
        await jobs.finished(OPS, job.action_id, "succeeded", "")
    with pytest.raises(ActionError, match="unknown job"):
        await jobs.started(TEST, "nope")


async def test_the_state_machine_refuses_steps_out_of_order(jobs) -> None:
    job = await approved(jobs)
    with pytest.raises(ActionError):  # not delivered yet
        await jobs.started(TEST, job.action_id)
    await jobs.claim(TEST)
    with pytest.raises(ActionError):  # a result needs a start first
        await jobs.finished(TEST, job.action_id, "succeeded", "")
    await jobs.started(TEST, job.action_id)
    await jobs.started(TEST, job.action_id)  # a repeated start is a retry and fine
    with pytest.raises(ActionError):  # a rejection comes before a start
        await jobs.finished(TEST, job.action_id, "rejected", "")
    with pytest.raises(ActionError, match="status must be"):
        await jobs.finished(TEST, job.action_id, "approved", "")
    await jobs.finished(TEST, job.action_id, "failed", "exit 1")
    with pytest.raises(ActionError):  # a finished job takes no more results
        await jobs.finished(TEST, job.action_id, "succeeded", "")


async def test_a_rejection_by_the_runner_is_logged(jobs, sessions) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    done = await jobs.finished(TEST, job.action_id, "rejected", "the signature is not valid")
    assert done.status == "rejected"
    assert await events(jobs, job.id) == ["created", "approved", "delivered", "rejected"]


async def test_the_runner_summary_is_masked(jobs) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    await jobs.started(TEST, job.action_id)
    done = await jobs.finished(TEST, job.action_id, "failed", "mail to anna@example.com failed")
    assert "anna@example.com" not in done.summary


async def test_a_started_job_without_a_result_is_failed_by_the_sweep(jobs, sessions, clock) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    await jobs.started(TEST, job.action_id)
    clock.advance(timedelta(minutes=46))
    assert await jobs.expire() == 1
    assert (await events(jobs, job.id))[-1] == "failed"


async def test_a_reboot_approved_in_slack_starts_approved_and_can_exist_once(jobs, sessions) -> None:
    async with sessions() as session, session.begin():
        session.add(RebootRequest(host=TEST, requested_at=START, status="approved", token="x"))  # noqa: S106
    job = await jobs.propose(
        "reboot_scheduled", {"reboot_request": 1}, TEST, "system", approved_by=USER, reboot_request_id=1
    )
    assert job.status == "approved"
    assert await events(jobs, job.id) == ["created", "approved"]
    with pytest.raises(ActionError, match="already a job"):
        await jobs.propose(
            "reboot_scheduled", {"reboot_request": 1}, TEST, "system", approved_by=USER, reboot_request_id=1
        )


async def test_a_coolify_runbook_runs_on_any_server_that_lists_the_application(sessions, clock) -> None:
    app = "abcdefghijklmnop12345678"
    service = ActionService(sessions, clock, load_catalog(), KEY, {"web-9", OPS}, {"web-9": {app: "web"}}, locale=EN)
    assert (
        await service.propose("container_restart", {"application": app}, "web-9", USER)
    ).runbook == "container_restart"
    with pytest.raises(ActionError):  # the list is per server: the application is not on the other one
        await service.propose("container_restart", {"application": app}, OPS, USER)


async def test_a_runbook_restricted_to_named_servers_is_not_created_elsewhere(sessions, clock) -> None:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    data["runbooks"]["image_prune"]["hosts"] = [TEST]
    service = ActionService(sessions, clock, parse_catalog(data), KEY, {TEST, OPS}, locale=EN)
    assert (await service.propose("image_prune", {}, TEST, USER)).host == TEST
    with pytest.raises(ActionError, match="cannot run on"):
        await service.propose("image_prune", {}, OPS, USER)


@pytest.mark.parametrize(
    ("runbook", "params", "host"),
    [
        ("shell", {}, TEST),
        ("image_prune", {"x": 1}, TEST),
        ("container_restart", {"application": "../x"}, TEST),
        ("image_prune", {}, "unknown-host"),
        ("container_restart", {"application": "abcdefghijklmnop12345678"}, OPS),  # no application list for that server
    ],
)
async def test_a_job_outside_the_catalog_is_not_created(jobs, sessions, runbook, params, host) -> None:
    with pytest.raises(ActionError):
        await jobs.propose(runbook, params, host, USER)
    async with sessions() as session:
        assert (await session.scalars(select(ActionJob))).all() == []


async def test_without_a_signing_key_nothing_is_delivered(sessions, clock) -> None:
    unsigned = ActionService(sessions, clock, load_catalog(), None, {TEST}, locale=EN)
    await approved(unsigned)
    with pytest.raises(ActionError, match="signing"):
        await unsigned.claim(TEST)


async def test_the_heartbeat_keeps_the_last_poll(jobs, sessions, clock) -> None:
    await jobs.heartbeat(TEST, "v1", "abc")
    clock.advance(timedelta(minutes=1))
    await jobs.heartbeat(TEST, "v2", "def")
    async with sessions() as session:
        row = await session.get(RunnerHeartbeat, TEST)
    assert (row.version, row.catalog, row.last_seen_at) == ("v2", "def", clock())


# --- the HTTP API -------------------------------------------------------------------------------------------------


@pytest.fixture
def client(database_url, sessions):
    seed = base64.b64encode(KEY.private_bytes_raw()).decode()
    settings = Settings(
        database_url=database_url,
        runner_tokens={TEST: TOK_TEST, OPS: TOK_OPS},
        runner_signing_key=seed,
    )
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        yield client


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def seed_job(client, host: str = TEST) -> str:
    async def go() -> str:
        job = await client.app.state.action_jobs.propose("image_prune", {}, host, USER)
        await client.app.state.action_jobs.approve(job.action_id, USER)
        return job.action_id

    return client.portal.call(go)


def test_the_api_needs_the_token_of_a_server(client) -> None:
    assert client.post("/api/v1/runner/poll", json={}).status_code == 401
    assert client.post("/api/v1/runner/poll", json={}, headers=auth("nope")).status_code == 401
    assert client.post("/api/v1/runner/poll", json={}, headers=auth("")).status_code == 401
    assert client.post("/api/v1/runner/jobs/x/started", headers=auth("nope")).status_code == 401


def test_a_poll_without_work_is_204_and_counts_as_heartbeat(client) -> None:
    assert (
        client.post("/api/v1/runner/poll", json={"version": "1", "catalog": "c"}, headers=auth(TOK_TEST)).status_code
        == 204
    )


def test_the_runner_fetches_runs_and_reports_a_job(client) -> None:
    action_id = seed_job(client)
    polled = client.post("/api/v1/runner/poll", json={}, headers=auth(TOK_TEST))
    assert polled.status_code == 200
    assert polled.json()["job"]["action_id"] == action_id
    assert client.post("/api/v1/runner/poll", json={}, headers=auth(TOK_TEST)).status_code == 204  # once only
    assert client.post(f"/api/v1/runner/jobs/{action_id}/started", headers=auth(TOK_TEST)).status_code == 204
    done = client.post(
        f"/api/v1/runner/jobs/{action_id}/result",
        json={"status": "succeeded", "summary": "ok"},
        headers=auth(TOK_TEST),
    )
    assert done.status_code == 204
    again = client.post(f"/api/v1/runner/jobs/{action_id}/result", json={"status": "succeeded"}, headers=auth(TOK_TEST))
    assert again.status_code == 409


def test_the_other_servers_token_cannot_fetch_or_report_the_job(client) -> None:
    action_id = seed_job(client)
    assert client.post("/api/v1/runner/poll", json={}, headers=auth(TOK_OPS)).status_code == 204
    assert client.post(f"/api/v1/runner/jobs/{action_id}/started", headers=auth(TOK_OPS)).status_code == 409
    assert client.post("/api/v1/runner/poll", json={}, headers=auth(TOK_TEST)).status_code == 200


def test_the_api_is_off_without_tokens(database_url, sessions) -> None:
    with TestClient(
        create_app(Settings(database_url=database_url), chat=FakeChat(), pager=FakePager(), clock=Clock(START))
    ) as bare:
        assert bare.post("/api/v1/runner/poll", json={}, headers=auth("x")).status_code == 503


async def test_a_start_after_the_expiry_is_refused_and_the_job_expires(jobs, clock) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    clock.advance(VALID_FOR)
    with pytest.raises(ActionError, match="expired"):
        await jobs.started(TEST, job.action_id)
    assert (await events(jobs, job.id))[-1] == "expired"


async def test_a_result_that_comes_after_the_lost_mark_still_counts(jobs, clock) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    await jobs.started(TEST, job.action_id)
    clock.advance(timedelta(minutes=46))
    await jobs.expire()
    done = await jobs.finished(TEST, job.action_id, "succeeded", "done after 31 minutes")
    assert (done.status, done.summary) == ("succeeded", "done after 31 minutes")
    with pytest.raises(ActionError):  # but only once
        await jobs.finished(TEST, job.action_id, "failed", "again")


def test_two_servers_cannot_share_a_runner_token() -> None:
    with pytest.raises(ValueError, match="own token"):
        Settings(runner_tokens={TEST: "s" * 40, OPS: "s" * 40})


def test_a_poll_without_a_body_is_a_heartbeat(client) -> None:
    assert client.post("/api/v1/runner/poll", headers=auth(TOK_TEST)).status_code == 204


def test_a_short_or_empty_runner_token_is_refused() -> None:
    for token in ("", "short"):
        with pytest.raises(ValueError, match="at least"):
            Settings(runner_tokens={TEST: token})


def test_a_runner_token_cannot_be_a_collector_token() -> None:
    with pytest.raises(ValueError, match="collector token"):
        Settings(runner_tokens={TEST: TOK_TEST}, host_report_tokens={TEST: TOK_TEST})


async def test_a_runner_cannot_fake_the_lost_mark(jobs) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    await jobs.started(TEST, job.action_id)
    await jobs.finished(TEST, job.action_id, "failed", "No result from the runner.")
    with pytest.raises(ActionError):
        await jobs.finished(TEST, job.action_id, "succeeded", "rewritten")


async def test_a_retried_start_is_accepted_but_not_after_a_result(jobs) -> None:
    job = await approved(jobs)
    await jobs.claim(TEST)
    await jobs.started(TEST, job.action_id)
    await jobs.started(TEST, job.action_id)
    await jobs.finished(TEST, job.action_id, "succeeded", "")
    with pytest.raises(ActionError):
        await jobs.started(TEST, job.action_id)


async def test_nothing_else_is_delivered_while_a_job_runs_on_the_server(jobs) -> None:
    first, second = await approved(jobs), await approved(jobs)
    assert (await jobs.claim(TEST))["job"]["action_id"] == first.action_id
    assert await jobs.claim(TEST) is None  # delivered, not finished
    await jobs.started(TEST, first.action_id)
    assert await jobs.claim(TEST) is None
    await jobs.finished(TEST, first.action_id, "succeeded", "")
    assert (await jobs.claim(TEST))["job"]["action_id"] == second.action_id


async def test_an_approval_with_no_time_left_to_run_is_refused(jobs, clock) -> None:
    job = await jobs.propose("image_prune", {}, TEST, USER)
    clock.advance(VALID_FOR - timedelta(seconds=30))
    assert await jobs.approve(job.action_id, USER) == "The approval has expired."
