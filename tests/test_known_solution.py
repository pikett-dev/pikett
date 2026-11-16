from datetime import timedelta

from sqlalchemy import select

from app.incidents.memory import latest_backed_analysis
from app.models import Incident, IncidentAnalysis
from tests.fakes import ScriptedLlm
from tests.test_analysis_service import answer, make, open_incident, rows
from tests.test_incident_memory import add_analysis, alert

SOLUTION = {
    "summary": "Disk full",
    "cause": "Disk full",
    "evidence": [],
    "confidence": "medium",
    "affected": "app-1",
    "immediate_action": "Run image_prune",
    "fix_suggestion": "Add a rotation",
    "risk": "low",
}


class NoModel(ScriptedLlm):
    """A model that must not be called: the point of a known solution."""

    async def complete(self, **kwargs):
        raise AssertionError("the model was called for a known problem")


async def solved_before(service, sessions, clock, *, feedback="helpful", **labels):
    """An earlier incident of the alarm with a backed analysis, already resolved."""
    await service.handle_alerts([alert(**labels)])
    await add_analysis(sessions, 1, clock, analysis=SOLUTION)
    async with sessions() as session, session.begin():
        row = (await session.scalars(select(IncidentAnalysis))).one()
        row.feedback = feedback
        row.posted_at = clock.now  # it was told back then
    clock.advance(timedelta(minutes=5))
    await service.handle_alerts([alert(**labels, ends=clock.now)])
    clock.advance(timedelta(hours=2))


async def open_incident_with(service, **labels):
    await service.handle_alerts([alert(**labels)])


async def incident(sessions, incident_id) -> Incident:
    async with sessions() as session:
        return await session.get(Incident, incident_id)  # type: ignore[return-value]


async def test_a_known_problem_gets_the_earlier_solution_and_no_model_call(service, sessions, chat, clock):
    await solved_before(service, sessions, clock, host="app-1")
    await open_incident_with(service, host="app-1")
    llm = NoModel([])
    analysis = make(sessions, chat, clock, llm=llm)

    await analysis.tick()
    await analysis.wait_idle()

    assert llm.calls == [] and [r.incident_id for r in await rows(sessions)] == [1]  # only the earlier analysis
    [reply] = [r for r in chat.replies if "Known problem" in r]
    assert "Known problem" in reply and "Incident #1" in reply and "Disk full" in reply
    assert "Run image_prune" in reply and "http://ops.test/incidents/2" in reply
    second = await incident(sessions, 2)
    assert second.known_from_incident_id == 1 and second.known_posted_at is not None


async def test_it_is_told_once(service, sessions, chat, clock):
    await solved_before(service, sessions, clock)
    await open_incident_with(service)
    analysis = make(sessions, chat, clock, llm=NoModel([]))
    await analysis.tick()
    await analysis.tick()
    assert len([r for r in chat.replies if "Known problem" in r]) == 1


async def test_a_solution_nobody_marked_helpful_is_not_known(service, sessions, chat, clock):
    await solved_before(service, sessions, clock, feedback="not_helpful")
    await open_incident_with(service)
    analysis = make(sessions, chat, clock, [])
    await analysis.tick()
    assert (await incident(sessions, 2)).known_from_incident_id is None
    assert not [r for r in chat.replies if "Known problem" in r]


async def test_an_unknown_problem_is_analysed_as_before(service, sessions, chat, clock):
    await open_incident(service)  # no earlier incident at all
    llm = ScriptedLlm([])
    analysis = make(sessions, chat, clock, llm=llm)
    await analysis.tick()
    assert (await incident(sessions, 1)).known_from_incident_id is None
    assert [r.requested_by for r in await rows(sessions)] == ["auto"]


async def test_a_failed_post_is_retried_and_still_costs_no_model_call(service, sessions, chat, clock):
    await solved_before(service, sessions, clock)
    await open_incident_with(service)
    llm = NoModel([])
    analysis = make(sessions, chat, clock, llm=llm)
    chat.fail_reply = True
    await analysis.tick()
    assert (await incident(sessions, 2)).known_posted_at is None and llm.calls == []
    chat.fail_reply = False
    await analysis.tick()
    assert (await incident(sessions, 2)).known_posted_at is not None
    assert len([r for r in chat.replies if "Known problem" in r]) == 1


async def test_the_button_still_starts_an_analysis_of_a_known_problem(service, sessions, chat, clock):
    await solved_before(service, sessions, clock)
    await open_incident_with(service)
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.tick()
    assert await analysis.request(2, "U_ALICE") is None
    await analysis.wait_idle()
    assert [r.requested_by for r in await rows(sessions)][-1] == "U_ALICE"


async def test_the_helpful_filter_is_part_of_the_memory_query(service, sessions, clock):
    await solved_before(service, sessions, clock, feedback="not_helpful")
    await open_incident_with(service)
    second = await incident(sessions, 2)
    async with sessions() as session:
        assert await latest_backed_analysis(session, second) is not None
        assert await latest_backed_analysis(session, second, helpful_only=True) is None


async def test_a_newer_not_helpful_verdict_retires_an_older_helpful_one(service, sessions, clock):
    await solved_before(service, sessions, clock)  # incident 1: helpful
    await service.handle_alerts([alert()])  # incident 2 with a newer analysis, rated not helpful
    clock.advance(timedelta(minutes=1))
    await add_analysis(sessions, 2, clock, analysis=SOLUTION)
    async with sessions() as session, session.begin():
        newer = (await session.scalars(select(IncidentAnalysis).order_by(IncidentAnalysis.id.desc()))).first()
        newer.feedback = "not_helpful"
    await service.handle_alerts([alert(ends=clock.now)])
    clock.advance(timedelta(hours=1))
    await service.handle_alerts([alert()])
    third = await incident(sessions, 3)

    async with sessions() as session:
        assert await latest_backed_analysis(session, third, helpful_only=True) is None


async def test_a_mark_whose_solution_is_gone_falls_back_to_a_normal_analysis(service, sessions, chat, clock):
    await solved_before(service, sessions, clock)
    await open_incident_with(service)
    analysis = make(sessions, chat, clock, [answer()])
    chat.fail_reply = True  # the post fails, so the mark stays
    await analysis.tick()
    assert (await incident(sessions, 2)).known_from_incident_id == 1
    async with sessions() as session, session.begin():
        first = (await session.scalars(select(IncidentAnalysis).order_by(IncidentAnalysis.id))).first()
        first.feedback = "not_helpful"  # the solution is retired in the meantime
    chat.fail_reply = False

    await analysis.tick()
    await analysis.wait_idle()

    assert (await incident(sessions, 2)).known_from_incident_id is None
    assert [r.requested_by for r in await rows(sessions)][-1] == "auto"  # analysed as usual


async def test_a_resolved_incident_is_not_told_about_a_known_solution(service, sessions, chat, clock):
    await solved_before(service, sessions, clock)
    await open_incident_with(service)
    analysis = make(sessions, chat, clock, llm=NoModel([]))
    chat.fail_reply = True
    await analysis.tick()
    await service.handle_alerts([alert(ends=clock.now)])
    chat.fail_reply = False
    await analysis.tick()
    assert not [r for r in chat.replies if "Known problem" in r]


async def test_the_same_alarm_of_another_service_is_not_a_known_problem(service, sessions, chat, clock):
    await solved_before(service, sessions, clock, **{"service.name": "core"})
    await open_incident_with(service, **{"service.name": "admin-frontend"})
    analysis = make(sessions, chat, clock, [answer()])
    await analysis.tick()
    await analysis.wait_idle()
    assert (await incident(sessions, 2)).known_from_incident_id is None
    assert [r.requested_by for r in await rows(sessions)][-1] == "auto"  # analysed, not given core's solution
