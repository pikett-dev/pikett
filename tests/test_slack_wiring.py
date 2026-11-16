import asyncio

import pytest
from pydantic import SecretStr
from slack_bolt.request.async_request import AsyncBoltRequest
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.async_slack_response import AsyncSlackResponse

from app.incidents.schemas import AlertIn
from app.notify.slack import SlackNotifier
from tests.fakes import EN


@pytest.fixture
async def notifier(actions, monkeypatch):
    async def fake_auth_test(self, **kwargs):
        data = {"ok": True, "user_id": "UBOT", "bot_id": "BBOT", "team_id": "T1", "url": "https://x.slack.com/"}
        return AsyncSlackResponse(
            client=self, http_verb="POST", api_url="", req_args={}, data=data, headers={}, status_code=200
        )

    monkeypatch.setattr(AsyncWebClient, "auth_test", fake_auth_test)
    notifier = SlackNotifier(
        SecretStr("xoxb-fake"), SecretStr("xapp-fake"), "C1", "C2", actions, lambda: "On call: Alice", locale=EN
    )
    yield notifier
    await notifier.stop()


async def eventually(condition) -> None:
    """Bolt runs the listener as its own task after it has acknowledged, so the effect shows up a moment later."""
    for _ in range(100):
        if condition():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition was not met in time")


def block_action(user: str, action_id: str, value: str) -> AsyncBoltRequest:
    body = {
        "type": "block_actions",
        "team": {"id": "T1"},
        "user": {"id": user, "team_id": "T1"},
        "api_app_id": "A1",
        "channel": {"id": "C1"},
        "actions": [{"type": "button", "action_id": action_id, "value": value, "block_id": "b"}],
        "response_url": "https://hooks.slack.test/actions/1",
    }
    return AsyncBoltRequest(body=body, mode="socket_mode")


async def test_button_press_reaches_the_service_through_bolt(notifier, service, chat):
    await service.handle_alerts([AlertIn(labels={"alertname": "X", "severity": "P2"})])

    response = await notifier._app.async_dispatch(block_action("U_ALICE", "incident_ack", "1"))

    assert response.status == 200
    await eventually(lambda: chat.updates)
    assert chat.updates[-1].acked_by == "U_ALICE"


async def test_button_press_of_a_stranger_changes_nothing_and_tells_them_so(notifier, service, chat, monkeypatch):
    await service.handle_alerts([AlertIn(labels={"alertname": "X", "severity": "P2"})])
    replies: list[dict] = []

    async def fake_send_dict(self, body):
        replies.append(body)

    monkeypatch.setattr("slack_sdk.webhook.async_client.AsyncWebhookClient.send_dict", fake_send_dict)

    response = await notifier._app.async_dispatch(block_action("U_STRANGER", "incident_ack", "1"))

    assert response.status == 200
    await eventually(lambda: replies)
    assert chat.updates == []
    assert replies[0]["text"] == "You are not allowed to do that."
    assert replies[0]["response_type"] == "ephemeral"


async def test_oncall_command_answers_with_the_rotation(notifier):
    answers: list[str] = []

    async def ack(text=""):
        answers.append(text)

    await notifier._on_oncall(ack)

    assert answers == ["On call: Alice"]


async def test_the_analyze_button_answers_with_a_confirmation_and_starts_the_analysis(
    notifier, service, actions, monkeypatch
):
    class FakeAnalysis:
        requests: list = []

        async def request(self, incident_id, requested_by, *, deep=False):
            self.requests.append((incident_id, requested_by, deep))

    actions.analysis = FakeAnalysis()
    await service.handle_alerts([AlertIn(labels={"alertname": "X", "severity": "P2"})])
    replies: list[dict] = []

    async def fake_send_dict(self, body):
        replies.append(body)

    monkeypatch.setattr("slack_sdk.webhook.async_client.AsyncWebhookClient.send_dict", fake_send_dict)

    response = await notifier._app.async_dispatch(block_action("U_ALICE", "incident_analyze", "1"))

    assert response.status == 200
    await eventually(lambda: replies)
    assert FakeAnalysis.requests == [(1, "U_ALICE", False)]
    assert "The analysis is running" in replies[0]["text"] and replies[0]["response_type"] == "ephemeral"

    deep = await notifier._app.async_dispatch(block_action("U_ALICE", "incident_analyze_deep", "1"))

    assert deep.status == 200
    await eventually(lambda: len(replies) == 2)
    assert FakeAnalysis.requests[-1] == (1, "U_ALICE", True)


async def test_the_reboot_button_reaches_the_reboot_questions_through_bolt(notifier, actions, monkeypatch):
    class FakeReboots:
        approvals: list = []

        async def approve(self, value, user_id):
            self.approvals.append((value, user_id))

    actions.reboots = FakeReboots()

    response = await notifier._app.async_dispatch(block_action("U_ALICE", "reboot_approve", "3:tok"))

    assert response.status == 200
    await eventually(lambda: FakeReboots.approvals)
    assert FakeReboots.approvals == [("3:tok", "U_ALICE")]


async def test_the_feedback_button_stores_the_verdict_and_replaces_the_buttons(notifier, actions, monkeypatch):
    class FakeFeedback:
        calls: list = []

        async def record_feedback(self, analysis_id, user_id, feedback):
            self.calls.append((analysis_id, user_id, feedback))

    actions.service = object()
    actions.analysis = FakeFeedback()
    replies: list[dict] = []

    async def fake_send_dict(self, body):
        replies.append(body)

    monkeypatch.setattr("slack_sdk.webhook.async_client.AsyncWebhookClient.send_dict", fake_send_dict)

    response = await notifier._app.async_dispatch(block_action("U_ALICE", "analysis_helpful", "4"))

    assert response.status == 200
    await eventually(lambda: replies)
    assert FakeFeedback.calls == [(4, "U_ALICE", "helpful")]
    assert "helpful" in replies[0]["text"] and replies[0]["replace_original"] is True
