import base64
from datetime import timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.actions.approvals import ACTION_ID, RunbookApprovals, message, runbook_prompt
from app.actions.service import VALID_FOR, ActionError, ActionService
from app.config import Settings
from app.main import create_app
from app.models import ActionJob, Incident, IncidentAnalysis
from app.notify.slack import ButtonActions
from runner.catalog import load_catalog
from tests.fakes import EN, START, Clock, FakeChat, FakePager, llm_reply
from tests.test_analysis_service import answer, make, open_incident
from tests.test_analyst import search_logs, submit
from tests.test_api import ALERT

HOST = "app-1"
APP = "abcdefghijklmnop12345678"
ALICE, STRANGER = "U_ALICE", "U_STRANGER"
KEY = Ed25519PrivateKey.generate()


@pytest.fixture
def jobs(sessions, clock) -> ActionService:
    return ActionService(sessions, clock, load_catalog(), KEY, {HOST}, {HOST: {APP: "core"}}, locale=EN)


@pytest.fixture
def approvals(sessions, jobs, chat, clock) -> RunbookApprovals:
    return RunbookApprovals(sessions, jobs, chat, clock, locale=EN)


@pytest.fixture
def buttons(approvals) -> ButtonActions:
    actions = ButtonActions([ALICE, "U_BOB"], EN)
    actions.approvals = approvals
    return actions


async def analysis_row(sessions, **fields: Any) -> IncidentAnalysis:
    """An incident analysis row (incident 1 must exist) with these fields in its JSON."""
    base = {"runbook": "image_prune", "runbook_host": HOST, "runbook_application": ""}
    async with sessions() as session, session.begin():
        row = IncidentAnalysis(
            incident_id=1,
            requested_by="auto",
            status="done",
            started_at=START,
            finished_at=START,
            verified=True,
            analysis={**base, **fields},
        )
        session.add(row)
        await session.flush()
        return row


async def all_jobs(sessions) -> list[ActionJob]:
    async with sessions() as session:
        return list((await session.scalars(select(ActionJob).order_by(ActionJob.id))).all())


def button_of(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    [actions] = [b for b in blocks if b["type"] == "actions"]
    [button] = actions["elements"]
    return button


async def test_a_proposal_becomes_a_job_and_a_button_with_a_confirmation_dialog(
    service, sessions, approvals, chat
) -> None:
    await open_incident(service)
    row = await analysis_row(sessions)
    await approvals.offer(row, "C1", "ts-1")

    [job] = await all_jobs(sessions)
    assert (job.runbook, job.host, job.status, job.requested_by, job.incident_id) == (
        "image_prune",
        HOST,
        "proposed",
        "analysis",
        1,
    )
    assert (job.slack_channel, job.slack_ts) == ("C1", "m-1")
    text, blocks = chat.messages[0]
    button = button_of(blocks)
    assert button["action_id"] == ACTION_ID and button["value"] == job.action_id
    assert button["confirm"]["title"]["text"] and button["confirm"]["confirm"]["text"] == "Approve"
    assert "Remove unused Docker images" in text and HOST in text and "low risk" in text


@pytest.mark.parametrize(
    "fields",
    [
        {"runbook": ""},
        {"runbook": "shell"},
        {"runbook": "reboot_scheduled"},  # created from the Slack approval of a reboot, never proposed
        {"runbook": "container_restart"},  # needs an application
        {"runbook": "container_restart", "runbook_application": "../x"},
        {"runbook": "container_restart", "runbook_application": "zzzzzzzzzzzzzzzzzzzzzzzz"},  # not on the list
        {"confidence": "low"},
        {"runbook_host": "unknown-host"},
        {"runbook_host": ""},
        {"runbook": "container_restart", "runbook_application": APP, "runbook_host": "ops-server"},
    ],
)
async def test_a_proposal_the_catalog_does_not_allow_gets_no_job_and_no_button(
    service, sessions, approvals, chat, fields
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions, **fields), "C1", "ts-1")
    assert await all_jobs(sessions) == [] and chat.messages == []


async def test_a_proposal_with_an_application_carries_it_as_a_parameter(service, sessions, approvals, chat) -> None:
    await open_incident(service)
    row = await analysis_row(sessions, runbook="container_restart", runbook_application=APP)
    await approvals.offer(row, "C1", "ts-1")
    [job] = await all_jobs(sessions)
    assert job.params == {"application": APP}
    text, blocks = chat.messages[0]
    assert f"application=core ({APP})" in text and "medium risk" in text  # the approver sees the name
    assert "core" in button_of(blocks)["confirm"]["text"]["text"]  # and so does the dialog


async def test_the_same_analysis_is_offered_once(service, sessions, approvals, chat) -> None:
    await open_incident(service)
    row = await analysis_row(sessions)
    await approvals.offer(row, "C1", "ts-1")
    await approvals.offer(row, "C1", "ts-1")  # a retried post
    assert len(await all_jobs(sessions)) == 1 and len(chat.messages) == 1


async def test_a_failed_post_leaves_a_job_that_simply_expires(service, sessions, approvals, chat, jobs, clock) -> None:
    await open_incident(service)
    chat.fail_next_post = True
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    assert job.slack_ts is None and job.status == "proposed"
    clock.advance(VALID_FOR)
    await jobs.expire()
    assert (await all_jobs(sessions))[0].status == "expired"  # nobody could approve it, nothing ran


async def test_only_allowed_users_approve_and_the_job_stays_proposed_for_a_stranger(
    service, sessions, approvals, buttons, chat
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    assert await buttons.handle_runbook(STRANGER, job.action_id) == "You are not allowed to do that."
    assert (await all_jobs(sessions))[0].status == "proposed"

    assert await buttons.handle_runbook(ALICE, job.action_id) is None
    approved = (await all_jobs(sessions))[0]
    assert (approved.status, approved.approved_by) == ("approved", ALICE)
    assert f"Approved by <@{ALICE}>" in chat.messages[0][0] and "Waiting for the runner" in chat.messages[0][0]
    assert not [b for b in chat.messages[0][1] if b["type"] == "actions"]  # the button is gone


async def test_a_second_click_starts_no_second_job(service, sessions, approvals, buttons, jobs) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    assert await buttons.handle_runbook(ALICE, job.action_id) is None
    assert await buttons.handle_runbook("U_BOB", job.action_id) == "This action is already approved or finished."
    assert await jobs.claim(HOST) is not None and await jobs.claim(HOST) is None  # one delivery, ever
    assert len(await all_jobs(sessions)) == 1


async def test_an_unknown_button_value_and_missing_wiring_answer_politely(buttons) -> None:
    assert await buttons.handle_runbook(ALICE, "nope") == "Unknown approval."
    bare = ButtonActions([ALICE], EN)
    assert await bare.handle_runbook(ALICE, "x") == "Actions are not set up."


async def test_the_message_follows_the_job_and_ends_with_the_result(
    service, sessions, approvals, buttons, jobs, chat, clock
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    await buttons.handle_runbook(ALICE, job.action_id)
    await jobs.claim(HOST)
    await approvals.tick()
    assert "picked up" in chat.messages[0][0]
    await jobs.started(HOST, job.action_id)
    await approvals.tick()
    assert "Running." in chat.messages[0][0]
    await jobs.finished(HOST, job.action_id, "succeeded", "Total reclaimed space: 1.2GB")
    await approvals.tick()
    assert ":white_check_mark: Done. Total reclaimed space: 1.2GB" in chat.messages[0][0]
    assert "health check running" in chat.messages[0][0]
    posted = len(chat.messages), chat.messages[0]
    await approvals.tick()  # nothing changed: no new update
    assert (len(chat.messages), chat.messages[0]) == posted


async def test_a_failure_and_a_rejection_and_an_expiry_are_shown(
    service, sessions, approvals, buttons, jobs, chat, clock
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    await buttons.handle_runbook(ALICE, job.action_id)
    await jobs.claim(HOST)
    await jobs.finished(HOST, job.action_id, "rejected", "the signature is not valid")
    await approvals.tick()
    assert ":no_entry:" in chat.messages[0][0] and "signature" in chat.messages[0][0]

    other = await analysis_row(sessions)
    await approvals.offer(other, "C1", "ts-1")
    clock.advance(VALID_FOR + timedelta(seconds=1))
    await jobs.expire()
    await approvals.tick()
    assert "Not approved, the deadline has passed" in chat.messages[1][0]


def test_the_prompt_lists_the_runbooks_without_the_reboot_and_is_empty_without_a_runner() -> None:
    text = runbook_prompt(load_catalog(), {HOST})
    assert "image_prune" in text and "container_restart" in text and "runbook_application" in text
    assert "reboot_scheduled" not in text and HOST in text
    assert runbook_prompt(load_catalog(), set()) == ""


def test_the_message_text_for_an_unknown_runbook_does_not_crash() -> None:
    job = ActionJob(
        action_id="a", runbook="gone", params={}, host=HOST, status="failed", summary="x", created_at=START,
        expires_at=START, requested_by="analysis", approved_by=ALICE, approved_at=START,
    )  # fmt: skip
    text, _ = message(EN, job, None)
    assert "gone" in text and "Failed" in text


# --- wiring: the analysis posts, the button is offered, the incident page shows the action ---------------------------


async def test_a_posted_analysis_with_a_proposal_offers_the_button_but_not_when_unverified(
    service, sessions, chat, clock, approvals
) -> None:
    await open_incident(service)
    analysis = make(sessions, chat, clock, [llm_reply(search_logs()), llm_reply(submit())])
    seen: list[int] = []

    async def hook(run, channel, ts):
        seen.append(run.id)
        await approvals.offer(run, channel, ts)

    analysis.on_posted = hook
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    async with sessions() as session, session.begin():
        row = (await session.scalars(select(IncidentAnalysis))).one()
        row.analysis = {**row.analysis, "runbook": "image_prune", "runbook_host": HOST}
    await analysis.tick()
    offers = [m for m in chat.messages if m[0] != "Was the analysis helpful?"]  # the feedback question comes next to it
    assert seen == [1] and len(await all_jobs(sessions)) == 1 and len(offers) == 1

    # An analysis without backing evidence is posted, but offers nothing.
    chat.messages.clear()
    unverified = make(sessions, chat, clock, [answer()])
    unverified.on_posted = hook
    await unverified.request(1, "U_BOB")
    await unverified.wait_idle()
    async with sessions() as session, session.begin():
        rows = (await session.scalars(select(IncidentAnalysis).order_by(IncidentAnalysis.id))).all()
        assert rows[-1].verified is False
        rows[-1].analysis = {**rows[-1].analysis, "runbook": "image_prune", "runbook_host": HOST}
    await unverified.tick()
    assert len(seen) == 1 and chat.messages == []


async def test_the_incident_page_shows_the_action_and_its_result(database_url, sessions) -> None:
    seed = base64.b64encode(KEY.private_bytes_raw()).decode()
    settings = Settings(database_url=database_url, runner_tokens={HOST: "t" * 40}, runner_signing_key=seed)
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        client.post("/api/v2/alerts", json=[ALERT])

        async def seed_job() -> None:
            jobs = client.app.state.action_jobs
            job = await jobs.propose("image_prune", {}, HOST, "analysis", incident_id=1)
            await jobs.approve(job.action_id, ALICE)
            await jobs.claim(HOST)
            await jobs.started(HOST, job.action_id)
            await jobs.finished(HOST, job.action_id, "succeeded", "Total reclaimed space: 1.2GB")

        client.portal.call(seed_job)
        page = client.get("/incidents/1").text
    assert "Actions" in page and "image_prune" in page and ALICE in page
    assert "Total reclaimed space: 1.2GB" in page and "succeeded" in page and "Health: pending" in page


async def test_nothing_is_offered_for_an_incident_that_is_resolved(service, sessions, approvals, chat) -> None:
    await open_incident(service)
    async with sessions() as session, session.begin():
        await session.execute(update(Incident).values(status="resolved"))
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    assert await all_jobs(sessions) == [] and chat.messages == []


async def test_a_runbook_the_ops_service_creates_itself_cannot_be_proposed_by_anyone_else(jobs) -> None:
    with pytest.raises(ActionError, match="itself"):
        await jobs.propose("reboot_scheduled", {"reboot_request": 1}, HOST, "analysis")


async def test_a_refresh_that_fails_does_not_undo_the_approval(
    service, sessions, approvals, buttons, chat, monkeypatch
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)

    async def broken(self_, *args):
        raise RuntimeError("slack is down")

    monkeypatch.setattr(type(chat), "update_message", broken)
    assert await buttons.handle_runbook(ALICE, job.action_id) is None
    assert (await all_jobs(sessions))[0].status == "approved"


async def test_an_approval_after_the_incident_resolved_is_refused_and_the_job_retired(
    service, sessions, approvals, buttons, chat
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    async with sessions() as session, session.begin():
        await session.execute(update(Incident).values(status="resolved"))
    assert await buttons.handle_runbook(ALICE, job.action_id) == "The alert is no longer open."
    assert (await all_jobs(sessions))[0].status == "expired"
    assert "deadline has passed" in chat.messages[0][0] and not [
        b for b in chat.messages[0][1] if b["type"] == "actions"
    ]


async def test_a_newer_proposal_retires_the_older_unapproved_one(service, sessions, approvals, buttons) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    old, new = await all_jobs(sessions)
    assert (old.status, new.status) == ("expired", "proposed")
    assert await buttons.handle_runbook(ALICE, old.action_id) == "This action is already approved or finished."


async def test_runner_output_cannot_ping_the_channel_or_make_links(
    service, sessions, approvals, buttons, jobs, chat
) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    await buttons.handle_runbook(ALICE, job.action_id)
    await jobs.claim(HOST)
    await jobs.started(HOST, job.action_id)
    await jobs.finished(HOST, job.action_id, "failed", "<!channel> see <https://evil.example|docs> & more")
    await approvals.tick()
    text = chat.messages[0][0]
    assert "<!channel>" not in text and "<https://evil" not in text and "&lt;!channel&gt;" in text and "&amp;" in text


async def test_a_message_keeps_the_state_it_was_drawn_from(service, sessions, approvals, jobs, chat) -> None:
    await open_incident(service)
    await approvals.offer(await analysis_row(sessions), "C1", "ts-1")
    [job] = await all_jobs(sessions)
    await approvals.approve(job.action_id, ALICE)
    drawn = (await all_jobs(sessions))[0]
    await jobs.claim(HOST)  # the job moves on while the message of the older state is being recorded
    await approvals._remember(drawn.id, approvals._state(drawn))
    await approvals.tick()
    assert "picked up" in chat.messages[0][0]  # the tick still redraws it


def test_the_prompt_lists_the_applications_by_name_and_uuid() -> None:
    text = runbook_prompt(load_catalog(), {HOST}, {HOST: {APP: "core"}})
    assert f"core = {APP}" in text
