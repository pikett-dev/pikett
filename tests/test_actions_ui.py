import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import Person, Settings
from app.main import create_app
from app.models import FixPr
from tests.fakes import Clock, FakeChat, FakePager

KEY = Ed25519PrivateKey.generate()
HOST = "app-1"
ALICE = Person(name="Alice", slack_user_id="U_ALICE", ntfy_topic="t")


@pytest.fixture
def clock() -> Clock:
    return Clock(datetime.now(UTC))


@pytest.fixture
def client(database_url, sessions, clock):
    settings = Settings(
        database_url=database_url,
        runner_tokens={HOST: "t" * 40},
        runner_signing_key=base64.b64encode(KEY.private_bytes_raw()).decode(),
        oncall_people=[ALICE],
        timezone="Europe/Vienna",
    )
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=clock)) as client:
        client.clock = clock
        yield client


def call(client, coro_fn):
    return client.portal.call(coro_fn)


def needs_you(page: str) -> str:
    """The text of the "Needs you" list (empty when there is none)."""
    start = page.find('<ul class="attn">')
    return page[start : page.find("</ul>", start)] if start >= 0 else ""


async def run_prune(client) -> int:
    jobs = client.app.state.action_jobs
    job = await jobs.propose("image_prune", {}, HOST, "analysis")
    await jobs.approve(job.action_id, "U_ALICE")
    await jobs.claim(HOST)
    await jobs.started(HOST, job.action_id)
    await jobs.finished(HOST, job.action_id, "succeeded", "Total reclaimed space: 1.2GB")
    return job.id


def test_every_action_is_in_the_history_with_runbook_approval_and_result(client) -> None:
    job_id = call(client, lambda: run_prune(client))
    page = client.get("/ops/history?kind=action").text
    assert "Action image_prune" in page and "approved by Alice" in page  # the name, not the Slack id
    assert "Total reclaimed space: 1.2GB" in page and "done" in page and "Actions" in page
    assert f"/ops/actions/{job_id}" in page
    assert "Action image_prune" not in client.get("/ops/history?kind=job").text  # its own kind


def test_a_container_restart_shows_its_parameters(client) -> None:
    async def go() -> None:
        jobs = client.app.state.action_jobs
        jobs.applications[HOST] = {"abcdefghijklmnop12345678": "core"}
        job = await jobs.propose("container_restart", {"application": "abcdefghijklmnop12345678"}, HOST, "analysis")
        await jobs.approve(job.action_id, "U_ALICE")

    call(client, go)
    page = client.get("/ops/history?kind=action").text
    assert "application=abcdefghijklmnop12345678" in page and "approved, waiting for the runner" in page


def test_the_detail_page_shows_the_audit_log_and_a_missing_action_is_404(client) -> None:
    job_id = call(client, lambda: run_prune(client))
    page = client.get(f"/ops/actions/{job_id}")
    assert page.status_code == 200
    for step in ("created", "approved", "delivered", "started", "succeeded"):
        assert step in page.text
    assert "Alice" in page.text and "Total reclaimed space" in page.text and "Afterwards" in page.text
    assert client.get("/ops/actions/9999").status_code == 404


def test_a_fix_pull_request_is_in_the_history(client) -> None:
    from tests.test_api import ALERT

    client.post("/api/v2/alerts", json=[ALERT])

    async def go() -> None:
        async with client.app.state.sessions() as session, session.begin():
            from app.models import IncidentAnalysis

            analysis = IncidentAnalysis(incident_id=1, requested_by="auto", status="done", started_at=client.clock())
            session.add(analysis)
            await session.flush()
            session.add(
                FixPr(
                    token="t", analysis_id=analysis.id, repo="acme/core", title="Use the right value",  # noqa: S106
                    diff="x", branch="ops-fix/x", status="created", created_at=client.clock(),
                    expires_at=client.clock(), approved_by="U_ALICE", approved_at=client.clock(),
                    pr_url="https://bitbucket.org/acme/core/pull-requests/7", incident_id=1,
                )
            )  # fmt: skip

    call(client, go)
    page = client.get("/ops/history?kind=action").text
    assert "Fix PR acme/core: Use the right value" in page and "PR created" in page
    assert "https://bitbucket.org/acme/core/pull-requests/7" in page and "approved by Alice" in page


def test_a_runner_that_never_reported_is_a_card_but_needs_nobody(client) -> None:
    page = client.get("/ops").text
    assert f"Runner on {HOST}" in page and "never reported" in page
    assert "Runner on" not in needs_you(page)


def test_a_fresh_runner_is_ok_and_a_silent_one_needs_you(client) -> None:
    jobs = client.app.state.action_jobs
    call(client, lambda: jobs.heartbeat(HOST, "0.1", jobs.catalog.digest))
    page = client.get("/ops").text
    assert f"Runner on {HOST}" in page and "The runner reported" in page and "Runner on" not in needs_you(page)

    client.clock.advance(timedelta(minutes=10))  # the heartbeat is now 10 minutes old (the page uses the real time)
    stale = datetime.now(UTC) - timedelta(minutes=10)

    async def age() -> None:
        from sqlalchemy import update

        from app.models import RunnerHeartbeat

        async with client.app.state.sessions() as session, session.begin():
            await session.execute(update(RunnerHeartbeat).values(last_seen_at=stale))

    call(client, age)
    page = client.get("/ops").text
    assert f"Runner on {HOST}" in needs_you(page) and "has not reported" in needs_you(page)
    assert "Approvals do not run" in page


def test_a_runner_with_another_catalog_gets_a_warning(client) -> None:
    jobs = client.app.state.action_jobs
    call(client, lambda: jobs.heartbeat(HOST, "0.1", "0" * 64))
    page = client.get("/ops").text
    assert "catalog differs" in page and f"Runner on {HOST}" in needs_you(page)


def test_the_runner_card_has_its_help_and_the_help_page_lists_it(client) -> None:
    call(client, lambda: client.app.state.action_jobs.heartbeat(HOST, "0.1", ""))
    assert f"What is Runner on {HOST}?" in client.get("/ops").text
    assert 'id="RunnerHeartbeat"' in client.get("/ops/help").text


def test_the_pages_work_without_a_runner(database_url, sessions) -> None:
    with TestClient(create_app(Settings(database_url=database_url), chat=FakeChat(), pager=FakePager())) as bare:
        assert bare.get("/ops").status_code == 200
        assert bare.get("/ops/history?kind=action").status_code == 200


def test_the_detail_page_masks_what_the_history_masks(client) -> None:
    async def go() -> int:
        jobs = client.app.state.action_jobs
        job = await jobs.propose("image_prune", {}, HOST, "analysis")
        await jobs.approve(job.action_id, "U_ALICE")
        await jobs.claim(HOST)
        await jobs.started(HOST, job.action_id)
        await jobs.finished(HOST, job.action_id, "failed", "mail to anna@example.com failed")
        return job.id

    page = client.get(f"/ops/actions/{call(client, go)}").text
    assert "anna@example.com" not in page


def test_a_result_is_a_sign_of_life_of_the_runner(client) -> None:
    jobs = client.app.state.action_jobs
    call(client, lambda: jobs.heartbeat(HOST, "0.1", jobs.catalog.digest))
    client.clock.advance(timedelta(minutes=20))  # a long job: the runner did not poll meanwhile
    call(client, lambda: run_prune(client))

    async def last_seen():
        from app.models import RunnerHeartbeat

        async with client.app.state.sessions() as session:
            return (await session.get(RunnerHeartbeat, HOST)).last_seen_at

    assert call(client, last_seen) == client.clock()


def test_the_overview_shows_no_slack_shortcodes_and_a_catalog_mismatch_leads(client) -> None:
    jobs = client.app.state.action_jobs
    call(client, lambda: jobs.heartbeat(HOST, "0.1", "0" * 64))
    page = client.get("/ops").text
    assert ":red_circle:" not in page and ":warning:" not in page
    assert "Its catalog differs" in needs_you(page) and "The runner reported" not in needs_you(page)


def test_a_failing_runner_card_still_leaves_a_page_and_a_warning(client, monkeypatch) -> None:
    async def broken(*args, **kwargs):
        raise RuntimeError("database says no")

    monkeypatch.setattr("app.web.activity.runner_rows", broken)
    page = client.get("/ops")
    assert page.status_code == 200 and "The runner cards cannot be read right now" in page.text


def test_a_running_action_keeps_the_card_green_and_an_unapproved_proposal_is_no_warning(client) -> None:
    async def go() -> None:
        jobs = client.app.state.action_jobs
        await jobs.heartbeat(HOST, "0.1", jobs.catalog.digest)
        job = await jobs.propose("image_prune", {}, HOST, "analysis")
        await jobs.approve(job.action_id, "U_ALICE")
        await jobs.claim(HOST)
        await jobs.started(HOST, job.action_id)
        unapproved = await jobs.propose("apt_security", {}, HOST, "analysis")
        await jobs.cancel(unapproved.action_id, "test")

    call(client, go)
    client.clock.advance(timedelta(minutes=10))
    page = client.get("/ops").text
    assert "An action is running" in page and "Runner on" not in needs_you(page)
    history = client.get("/ops/history?kind=action&status=warn").text
    assert "apt_security" not in history  # not a warning: nobody approved it


def test_a_job_id_beyond_the_database_range_is_a_404_not_a_crash(client) -> None:
    assert client.get("/ops/actions/99999999999999999999").status_code == 422  # rejected before it reaches Postgres
