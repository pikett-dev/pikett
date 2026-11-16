from datetime import timedelta

from app.incidents.schemas import AlertIn
from app.notify.slack import ButtonActions
from tests.fakes import EN


async def open_incident(service) -> None:
    await service.handle_alerts([AlertIn(labels={"alertname": "X", "severity": "P1"})])


async def test_allowed_user_acknowledges(actions, service, chat):
    await open_incident(service)

    assert await actions.handle("U_ALICE", "incident_ack", 1) is None
    assert chat.updates[-1].acked_by == "U_ALICE"


async def test_stranger_is_refused_and_nothing_changes(actions, service, chat):
    await open_incident(service)

    assert await actions.handle("U_STRANGER", "incident_ack", 1) == "You are not allowed to do that."
    assert chat.updates == []


async def test_silence_buttons_set_the_duration(actions, service, sessions, clock):
    from app.models import Incident

    await open_incident(service)
    await actions.handle("U_ALICE", "incident_silence_24h", 1)

    async with sessions() as session:
        incident = await session.get(Incident, 1)
    assert incident.silenced_until == clock.now + timedelta(hours=24)


async def test_unknown_action_and_closed_incident_give_a_message(actions, service):
    await open_incident(service)

    assert await actions.handle("U_ALICE", "incident_delete", 1) == "Unknown action."
    assert await actions.handle("U_ALICE", "incident_ack", 99) == "The alert is no longer open."


async def test_before_the_service_is_ready():
    assert await ButtonActions(["U_ALICE"], EN).handle("U_ALICE", "incident_ack", 1) == "The service is still starting."


class FakeAnalysis:
    def __init__(self, answer=None):
        self.answer = answer
        self.requests = []

    async def request(self, incident_id, requested_by, *, deep=False):
        self.requests.append((incident_id, requested_by, deep))
        return self.answer


async def test_the_analyze_button_starts_an_analysis_for_an_allowed_user(actions):
    actions.analysis = FakeAnalysis()
    assert await actions.handle("U_ALICE", "incident_analyze", 5) is None
    assert actions.analysis.requests == [(5, "U_ALICE", False)]


async def test_the_opus_button_asks_for_the_deep_model(actions):
    actions.analysis = FakeAnalysis()
    assert await actions.handle("U_ALICE", "incident_analyze_deep", 5) is None
    assert actions.analysis.requests == [(5, "U_ALICE", True)]


async def test_the_analyze_button_passes_on_the_reason_when_nothing_starts(actions):
    actions.analysis = FakeAnalysis("An analysis is already running for this alert.")
    assert await actions.handle("U_ALICE", "incident_analyze", 5) == "An analysis is already running for this alert."


async def test_a_stranger_cannot_start_an_analysis_and_without_the_agent_there_is_a_message(actions):
    actions.analysis = FakeAnalysis()
    assert await actions.handle("U_STRANGER", "incident_analyze", 5) == "You are not allowed to do that."
    assert actions.analysis.requests == []
    actions.analysis = None
    assert "not set up" in (await actions.handle("U_ALICE", "incident_analyze", 5) or "")
