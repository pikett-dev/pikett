from sqlalchemy import select

from app.models import IncidentAnalysis
from app.notify.blocks import FEEDBACK_HELPFUL, FEEDBACK_NOT_HELPFUL, feedback_blocks
from tests.fakes import EN, llm_reply
from tests.test_analysis_service import answer, make, open_incident, rows
from tests.test_analyst import search_logs, submit


def test_the_question_has_two_buttons_carrying_the_analysis_id():
    section, actions = feedback_blocks(EN, 7)
    assert section["text"]["text"] == "Was the analysis helpful?"
    assert [(e["action_id"], e["value"]) for e in actions["elements"]] == [
        (FEEDBACK_HELPFUL, "7"),
        (FEEDBACK_NOT_HELPFUL, "7"),
    ]


async def test_a_finished_analysis_gets_the_feedback_question_in_its_thread(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [llm_reply(search_logs()), llm_reply(submit())])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    await analysis.tick()

    assert [text for text, _ in chat.messages] == ["Was the analysis helpful?"]
    await analysis.tick()
    assert len(chat.messages) == 1  # asked once


async def test_an_analysis_without_backing_evidence_gets_no_feedback_question(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()])  # its quote is not in any query result
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    await analysis.tick()
    assert [r.verified for r in await rows(sessions)] == [False] and chat.messages == []


async def test_a_failed_analysis_gets_no_feedback_question(service, sessions, chat, clock):
    from app.agent.llm import LlmError

    await open_incident(service)
    analysis = make(sessions, chat, clock, [LlmError("boom")])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    await analysis.tick()
    assert chat.messages == []


async def test_the_verdict_is_stored_and_the_latest_click_wins(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [llm_reply(search_logs()), llm_reply(submit())])
    await analysis.request(1, "U_ALICE")
    await analysis.wait_idle()
    [row] = await rows(sessions)

    assert await analysis.record_feedback(row.id, "U_ALICE", "helpful") is None
    assert await analysis.record_feedback(row.id, "U_BOB", "not_helpful") is None

    [row] = await rows(sessions)
    assert (row.feedback, row.feedback_by, row.feedback_at) == ("not_helpful", "U_BOB", clock.now)


async def test_a_verdict_for_an_unknown_or_unfinished_analysis_is_refused(service, sessions, chat, clock):
    await open_incident(service)
    analysis = make(sessions, chat, clock, [answer()])
    assert await analysis.record_feedback(999, "U_ALICE", "helpful") == "Analysis not found."
    async with sessions() as session, session.begin():
        session.add(IncidentAnalysis(incident_id=1, requested_by="auto", status="running", started_at=clock.now))
    async with sessions() as session:
        running_id = await session.scalar(select(IncidentAnalysis.id).where(IncidentAnalysis.status == "running"))
    assert await analysis.record_feedback(running_id, "U_ALICE", "helpful") == "Analysis not found."


class FeedbackAnalysis:
    def __init__(self, answer=None):
        self.answer = answer
        self.calls = []

    async def record_feedback(self, analysis_id, user_id, feedback):
        self.calls.append((analysis_id, user_id, feedback))
        return self.answer


async def test_the_feedback_button_is_for_allowed_users_and_known_actions(actions):
    actions.analysis = FeedbackAnalysis()
    assert await actions.handle_feedback("U_ALICE", FEEDBACK_HELPFUL, "5") is None
    assert await actions.handle_feedback("U_ALICE", FEEDBACK_NOT_HELPFUL, "5") is None
    assert actions.analysis.calls == [(5, "U_ALICE", "helpful"), (5, "U_ALICE", "not_helpful")]
    assert await actions.handle_feedback("U_STRANGER", FEEDBACK_HELPFUL, "5") == "You are not allowed to do that."
    assert await actions.handle_feedback("U_ALICE", FEEDBACK_HELPFUL, "x") == "Unknown action."
    assert await actions.handle_feedback("U_ALICE", "other", "5") == "Unknown action."
    actions.analysis = None
    assert "not set up" in (await actions.handle_feedback("U_ALICE", FEEDBACK_HELPFUL, "5") or "")
