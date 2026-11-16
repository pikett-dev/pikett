import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.agent.analyst import AnalysisOutcome, Analyst
from app.agent.budget import Budget, MeteredLlm
from app.agent.llm import LlmError
from app.agent.ports import Sources
from app.agent.service import (
    ANNOUNCE_WINDOW,
    MAX_AUTO_ATTEMPTS,
    RETRY_AFTER,
    AnalysisService,
    fail_interrupted_analyses,
)
from app.agent.tools import build_registry
from app.agent.usage import LlmUsage
from app.models import IncidentAnalysis
from tests.fakes import EN, NOW, FakeChat, FakeLedger, FakeLogs, FakeMetrics, FakeTraces, ScriptedLlm, llm_reply
from tests.test_analyst import LOG_LINE, search_logs, submit
from tests.test_service import firing

OPUS, SONNET, HAIKU = "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"


def make(sessions, chat, clock, replies=(), *, spent=0.0, auto=True, max_parallel=2, llm=None, stages=False):
    sources = Sources(FakeLogs([{"_msg": LOG_LINE}]), FakeMetrics(), FakeTraces())
    ledger = FakeLedger(spent)
    if stages:  # the real tier table, so a model missing from it fails here as it would in production
        budget = Budget.daily(ledger, SONNET, HAIKU, 5.0, deep=OPUS)
        model_port = MeteredLlm(llm or ScriptedLlm(list(replies)), budget)
    else:
        budget = Budget.daily(ledger, OPUS, HAIKU, 5.0)
        model_port = llm or ScriptedLlm(list(replies))
    analyst = Analyst(
        model_port,
        lambda masker: build_registry(sources, masker, clock=lambda: NOW),
        model=SONNET if stages else OPUS,
        max_iterations=6,
        max_tokens=100,
        timeout_seconds=10,
    )
    models = {"auto_model": HAIKU, "deep_model": OPUS} if stages else {}
    return AnalysisService(
        sessions,
        analyst,
        budget,
        chat,
        clock,
        "http://ops.test",
        auto=auto,
        max_parallel=max_parallel,
        locale=EN,
        **models,
    )


def answer():
    return llm_reply(submit(evidence=[]))


async def rows(sessions) -> list[IncidentAnalysis]:
    async with sessions() as session:
        return list((await session.scalars(select(IncidentAnalysis).order_by(IncidentAnalysis.id))).all())


async def open_incident(service, severity="P2", name="DiskAlmostFull"):
    await service.handle_alerts([firing(name, severity)])


async def test_a_requested_analysis_is_stored_and_the_tick_posts_it_to_the_thread_once(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [llm_reply(search_logs()), llm_reply(submit())])
    assert await analysis.request(1, "U_ALICE") is None
    await analysis.wait_idle()

    [row] = await rows(sessions)
    assert (row.status, row.requested_by, row.verified, row.model) == ("done", "U_ALICE", True, OPUS)
    assert row.analysis and row.analysis["confidence"] == "medium"
    assert row.cost_usd and row.cost_usd > 0 and row.iterations == 2 and row.tool_calls == 1
    assert row.posted_at is None and chat.replies == []  # stored first; posting is a tick step

    await analysis.tick()
    reply = chat.replies[-1]
    assert "AI analysis" in reply and "Connection is not available" in reply and "http://ops.test/incidents/1" in reply
    assert (await rows(sessions))[0].posted_at is not None
    await analysis.tick()
    assert len(chat.replies) == 1  # not posted twice


async def test_the_stages_run_on_haiku_automatically_on_sonnet_by_button_and_on_opus_on_request(
    service, sessions, chat, clock
):
    llm = ScriptedLlm([answer(), answer(), answer()])
    analysis = make(sessions, chat, clock, llm=llm, stages=True)
    await open_incident(service)
    await analysis.tick()
    await analysis.wait_idle()
    assert await analysis.request(1, "U_ALICE") is None
    await analysis.wait_idle()
    assert await analysis.request(1, "U_ALICE", deep=True) is None
    await analysis.wait_idle()
    assert [call["model"] for call in llm.calls] == [HAIKU, SONNET, OPUS]


async def test_over_the_budget_both_buttons_run_on_the_cheap_model(service, sessions, chat, clock):
    llm = ScriptedLlm([answer(), answer()])
    analysis = make(sessions, chat, clock, llm=llm, stages=True, spent=6.0)
    await open_incident(service)
    assert await analysis.request(1, "U_ALICE") is None
    await analysis.wait_idle()
    assert await analysis.request(1, "U_ALICE", deep=True) is None
    await analysis.wait_idle()
    assert [call["model"] for call in llm.calls] == [HAIKU, HAIKU]


async def test_a_failed_manual_analysis_is_visible_and_changes_nothing_else(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [LlmError("model API call failed (RateLimitError, 429)")])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    await analysis.tick()
    [row] = await rows(sessions)
    assert row.status == "failed" and "RateLimitError" in (row.error or "") and row.analysis is None
    assert chat.replies[-1].startswith(":warning: The AI analysis failed")  # manual: told right away


async def test_a_second_request_while_one_runs_is_refused(service, sessions, chat, clock):
    release = asyncio.Event()

    class Blocking(ScriptedLlm):
        async def complete(self, **kwargs):
            await release.wait()
            return await super().complete(**kwargs)

    await open_incident(service)
    analysis = make(sessions, chat, clock, llm=Blocking([answer()]))
    assert await analysis.request(1, "U_ALICE") is None
    assert await analysis.request(1, "U_BOB") == "An analysis is already running for this alert."
    release.set()
    await analysis.wait_idle()
    assert [r.status for r in await rows(sessions)] == ["done"]


async def test_nothing_starts_when_the_budget_is_used_up_or_the_incident_is_unknown(service, sessions, chat, clock):
    await open_incident(service)
    assert "daily budget" in (await make(sessions, chat, clock, spent=10.0).request(1, "U_ALICE") or "")
    assert await make(sessions, chat, clock).request(999, "U_ALICE") == "Alert not found."
    assert await rows(sessions) == []


@pytest.mark.parametrize(
    ("severity", "auto", "expected"), [("P2", True, 1), ("P1", True, 1), ("P3", True, 0), ("P2", False, 0)]
)
async def test_the_tick_starts_an_analysis_for_open_p1_and_p2_incidents_only(
    service, sessions, chat, clock, severity, auto, expected
):
    analysis = make(sessions, chat, clock, [answer()], auto=auto)
    await open_incident(service, severity)
    await analysis.tick()
    await analysis.wait_idle()
    found = await rows(sessions)
    assert len(found) == expected and all(r.requested_by == "auto" for r in found)


async def test_an_incident_is_analysed_once_and_a_resolved_one_not_at_all(service, sessions, chat, clock):
    analysis = make(sessions, chat, clock, [answer(), answer()])
    await open_incident(service)
    await analysis.tick()
    await analysis.wait_idle()
    await analysis.tick()  # a finished analysis exists: no second one
    await analysis.wait_idle()
    assert len(await rows(sessions)) == 1


async def test_an_analysis_that_could_not_start_for_the_budget_is_started_once_the_budget_allows(
    service, sessions, chat, clock
):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()], spent=10.0)
    await analysis.tick()
    assert await rows(sessions) == []  # nothing lost: the incident stays eligible
    analysis._budget = Budget.daily(FakeLedger(0.0), OPUS, HAIKU, 5.0)  # a new day
    await analysis.tick()
    await analysis.wait_idle()
    assert [r.status for r in await rows(sessions)] == ["done"]


async def test_a_failed_automatic_analysis_is_retried_after_a_pause_and_reported_after_the_last_attempt(
    service, sessions, chat, clock
):
    await open_incident(service)
    failures = [LlmError("model API call failed (APIConnectionError, -)")] * MAX_AUTO_ATTEMPTS
    analysis = make(sessions, chat, clock, failures)
    for attempt in range(1, MAX_AUTO_ATTEMPTS + 1):
        await analysis.tick()
        await analysis.wait_idle()
        assert len(await rows(sessions)) == attempt
        await analysis.tick()  # too soon for the next attempt, and no failure message while a retry is pending
        assert len(await rows(sessions)) == attempt
        if attempt < MAX_AUTO_ATTEMPTS:
            assert chat.replies == []
        clock.advance(RETRY_AFTER + timedelta(seconds=1))
    await analysis.tick()
    await analysis.wait_idle()
    assert len(await rows(sessions)) == MAX_AUTO_ATTEMPTS  # no fourth attempt
    assert len(chat.replies) == 1 and chat.replies[0].startswith(":warning:")  # told once, at the end


async def test_a_retry_that_works_supersedes_the_earlier_failure_without_a_message_about_it(
    service, sessions, chat, clock
):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [LlmError("model API call failed (APIConnectionError, -)"), answer()])
    await analysis.tick()
    await analysis.wait_idle()
    clock.advance(RETRY_AFTER + timedelta(seconds=1))
    await analysis.tick()
    await analysis.wait_idle()
    await analysis.tick()
    assert (
        len(chat.replies) == 1
        and "AI analysis" in chat.replies[0]
        and ":warning: The AI analysis failed" not in chat.replies[0]
    )
    assert all(r.posted_at is not None for r in await rows(sessions))


async def test_a_result_that_could_not_be_posted_is_posted_on_a_later_tick(service, sessions, clock):
    class FlakyChat(FakeChat):
        down = True

        async def reply(self, channel, ts, text):
            if self.down:
                raise RuntimeError("slack is down")
            await super().reply(channel, ts, text)

    chat = FlakyChat()
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    await analysis.tick()
    assert chat.replies == [] and (await rows(sessions))[0].posted_at is None
    chat.down = False
    await analysis.tick()
    assert len(chat.replies) == 1


async def test_a_result_waits_for_the_thread_and_is_not_posted_after_the_window(service, sessions, chat, clock):
    chat.fail_next_post = True  # Slack is down when the incident opens: no thread yet
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    await analysis.tick()
    assert chat.replies == []  # nothing to answer in yet
    await service.tick()  # the incident is posted now
    await analysis.tick()
    assert len(chat.replies) == 1

    stale = make(sessions, FakeChat(), clock, [answer()])
    await stale._store(
        1, AnalysisOutcome(model=OPUS, usage=LlmUsage(), cost_usd=0.0, iterations=1, tool_calls=0, error="x")
    )
    clock.advance(ANNOUNCE_WINDOW + timedelta(minutes=1))
    await stale.tick()
    assert stale._chat.replies == []


async def test_only_a_limited_number_of_analyses_run_at_the_same_time(service, sessions, chat, clock):
    running = peak = 0
    release = asyncio.Event()

    class Counting(ScriptedLlm):
        async def complete(self, **kwargs):
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await release.wait()
            running -= 1
            return await super().complete(**kwargs)

    await open_incident(service, name="A")
    await open_incident(service, name="B")
    analysis = make(sessions, chat, clock, llm=Counting([answer(), answer()]), max_parallel=1)
    await analysis.request(1, "U_ALICE")
    await analysis.request(2, "U_ALICE")
    await asyncio.sleep(0.05)
    assert peak == 1  # the second waits for the first
    release.set()
    await analysis.wait_idle()
    assert [r.status for r in await rows(sessions)] == ["done", "done"]


async def test_an_analysis_that_was_running_at_shutdown_is_failed_at_start_and_retried_by_the_tick(
    service, sessions, chat, clock
):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()])
    async with sessions() as session, session.begin():
        session.add(IncidentAnalysis(incident_id=1, requested_by="auto", status="running", started_at=clock()))
    await analysis.fail_interrupted()
    assert (await rows(sessions))[0].status == "failed"
    clock.advance(RETRY_AFTER + timedelta(seconds=1))
    await analysis.tick()
    await analysis.wait_idle()
    assert [r.status for r in await rows(sessions)] == ["failed", "done"]


async def test_the_budget_status_is_available_for_the_incident_page(service, sessions, chat, clock):
    status = await make(sessions, chat, clock, spent=6.0).budget_status()
    assert (status.spent_usd, status.model, status.exhausted) == (6.0, HAIKU, False)


async def test_a_burst_of_incidents_does_not_start_more_analyses_than_the_service_can_hold(
    service, sessions, chat, clock
):
    release = asyncio.Event()

    class Blocking(ScriptedLlm):
        async def complete(self, **kwargs):
            await release.wait()
            return await super().complete(**kwargs)

    for name in "ABCDE":
        await open_incident(service, name=name)
    analysis = make(sessions, chat, clock, llm=Blocking([answer() for _ in range(5)]), max_parallel=1)
    await analysis.tick()
    assert len(await rows(sessions)) == 2  # twice the parallel limit, the rest waits for a later tick
    release.set()
    await analysis.wait_idle()
    await analysis.tick()
    await analysis.wait_idle()
    assert len(await rows(sessions)) == 4


async def test_a_failure_is_reported_when_the_budget_rules_out_the_retry(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [LlmError("model API call failed (APIConnectionError, -)")])
    await analysis.tick()
    await analysis.wait_idle()
    await analysis.tick()
    assert chat.replies == []  # a retry is pending
    analysis._budget = Budget.daily(FakeLedger(10.0), OPUS, HAIKU, 5.0)  # the budget is gone: no retry will come
    await analysis.tick()
    assert len(chat.replies) == 1 and chat.replies[0].startswith(":warning:")


async def test_restarts_do_not_use_up_the_automatic_attempts(service, sessions, chat, clock):
    await open_incident(service)
    async with sessions() as session, session.begin():
        for _ in range(MAX_AUTO_ATTEMPTS - 1):  # below the cap for interrupted attempts, and no failed attempt yet
            session.add(
                IncidentAnalysis(
                    incident_id=1,
                    requested_by="auto",
                    status="failed",
                    started_at=clock() - timedelta(hours=1),
                    finished_at=clock() - timedelta(hours=1),
                    error="Interrupted by a restart",
                    interrupted=True,
                )
            )
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.tick()
    await analysis.wait_idle()
    assert [r.status for r in await rows(sessions)][-1] == "done"


async def test_the_incident_page_survives_a_budget_that_cannot_be_read(database_url, sessions, monkeypatch):
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    from app.config import Settings
    from app.main import create_app
    from tests.fakes import ALICE, BOB, START, Clock, FakePager
    from tests.test_api import ALERT

    async def broken(self):
        raise RuntimeError("database blip")

    monkeypatch.setattr(AnalysisService, "budget_status", broken)
    settings = Settings(
        database_url=database_url,
        base_url="http://ops.test",
        oncall_people=[ALICE, BOB],
        anthropic_api_key=SecretStr("sk-test"),
        agent_auto_analyze=False,
        timezone="Europe/Vienna",
    )
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        client.post("/api/v2/alerts", json=[ALERT])
        page = client.get("/incidents/1")
    assert page.status_code == 200 and "AppServerSilent" in page.text and "Daily budget" not in page.text


async def test_a_run_that_keeps_taking_the_process_down_is_not_retried_for_ever(service, sessions, chat, clock):
    await open_incident(service)
    async with sessions() as session, session.begin():
        for _ in range(MAX_AUTO_ATTEMPTS):
            session.add(
                IncidentAnalysis(
                    incident_id=1,
                    requested_by="auto",
                    status="failed",
                    started_at=clock() - timedelta(hours=1),
                    finished_at=clock() - timedelta(hours=1),
                    interrupted=True,
                )
            )
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.tick()
    await analysis.wait_idle()
    assert len(await rows(sessions)) == MAX_AUTO_ATTEMPTS  # the cap for interrupted attempts is reached


async def test_shutdown_waits_a_moment_then_cancels_and_the_next_start_marks_the_run_interrupted(
    service, sessions, chat, clock
):
    class Never(ScriptedLlm):
        async def complete(self, **kwargs):
            await asyncio.Event().wait()

    await open_incident(service)
    analysis = make(sessions, chat, clock, llm=Never([]))
    await analysis.request(1, "U_ALICE")
    await asyncio.sleep(0.02)
    await analysis.wait_idle(timeout=0.05)  # returns although the analysis is still running
    assert [r.status for r in await rows(sessions)] == ["running"]
    await fail_interrupted_analyses(sessions, clock, EN)  # needs no agent: the next start clears the row
    [row] = await rows(sessions)
    assert row.status == "failed" and row.interrupted is True


async def test_a_result_is_not_sent_again_when_only_recording_it_failed(service, sessions, chat, clock, monkeypatch):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    real_sessions = analysis._sessions
    broken = {"on": True}

    def flaky():
        if broken["on"] and chat.replies:  # the reply is out; now the recording fails
            raise RuntimeError("database blip")
        return real_sessions()

    monkeypatch.setattr(analysis, "_sessions", flaky)
    await analysis.tick()
    assert len(chat.replies) == 1
    broken["on"] = False
    await analysis.tick()  # the recording works now, the reply is not repeated
    assert len(chat.replies) == 1
    assert (await rows(sessions))[0].posted_at is not None
