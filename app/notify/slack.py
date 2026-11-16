import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from pydantic import SecretStr
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_bolt.app.async_app import AsyncApp

from app.actions.approvals import ACTION_ID as RUNBOOK_ACTION
from app.actions.approvals import RunbookApprovals
from app.actions.fixpr import ACTION_ID as FIXPR_ACTION
from app.actions.fixpr import FixPullRequests
from app.agent.service import AnalysisService
from app.config import Person
from app.i18n import Locale
from app.incidents.service import IncidentService
from app.notify.base import IncidentView
from app.notify.blocks import (
    ANALYZE_ACTION,
    ANALYZE_DEEP_ACTION,
    FEEDBACK_ACTIONS,
    fallback_text,
    incident_blocks,
)
from app.security.reboot import ACTION_ID as REBOOT_ACTION
from app.security.reboot import RebootQuestions

log = logging.getLogger(__name__)

_ANALYZE = {ANALYZE_ACTION: False, ANALYZE_DEEP_ACTION: True}  # action id -> deep (Opus)
_SILENCE = {"incident_silence_1h": timedelta(hours=1), "incident_silence_24h": timedelta(hours=24)}


class ButtonActions:
    """What a button press does. Kept apart from Bolt so the permission check is easy to test."""

    def __init__(self, allowed_users: list[str], locale: Locale) -> None:
        self._allowed = set(allowed_users)
        self._locale = locale
        self.service: IncidentService | None = None
        self.analysis: AnalysisService | None = None
        self.reboots: RebootQuestions | None = None
        self.approvals: RunbookApprovals | None = None
        self.fix_prs: FixPullRequests | None = None

    async def handle(self, user_id: str, action_id: str, incident_id: int) -> str | None:
        """Run the action and return an error text for the user, or None on success."""
        if user_id not in self._allowed:
            return self._locale.t("errors.not_allowed")
        if self.service is None:
            return self._locale.t("errors.starting")
        if action_id in _ANALYZE:
            if self.analysis is None:
                return self._locale.t("errors.analysis_off")
            return await self.analysis.request(incident_id, user_id, deep=_ANALYZE[action_id])
        if action_id == "incident_ack":
            done = await self.service.acknowledge(incident_id, user_id)
        elif action_id in _SILENCE:
            done = await self.service.silence(incident_id, user_id, _SILENCE[action_id])
        else:
            return self._locale.t("errors.unknown_action")
        return None if done else self._locale.t("errors.incident_closed")

    async def handle_reboot(self, user_id: str, value: str) -> str | None:
        """The approval button of a reboot question. Same allowlist as the incident buttons."""
        if user_id not in self._allowed:
            return self._locale.t("errors.not_allowed")
        if self.reboots is None:
            return self._locale.t("errors.starting")
        return await self.reboots.approve(value, user_id)

    async def handle_runbook(self, user_id: str, value: str) -> str | None:
        """The approval button of a proposed runbook. Same allowlist as the other buttons."""
        if user_id not in self._allowed:
            return self._locale.t("errors.not_allowed")
        if self.approvals is None:
            return self._locale.t("errors.actions_off")
        return await self.approvals.approve(value, user_id)

    async def handle_feedback(self, user_id: str, action_id: str, value: str) -> str | None:
        """The Helpful / Not helpful buttons under an analysis. Same allowlist as the other buttons."""
        if user_id not in self._allowed:
            return self._locale.t("errors.not_allowed")
        if self.analysis is None:
            return self._locale.t("errors.analysis_off")
        if not value.isdecimal() or action_id not in FEEDBACK_ACTIONS:
            return self._locale.t("errors.unknown_action")
        return await self.analysis.record_feedback(int(value), user_id, FEEDBACK_ACTIONS[action_id])

    async def handle_fixpr(self, user_id: str, value: str) -> str | None:
        """The approval button of a fix pull request. Same allowlist as the other buttons."""
        if user_id not in self._allowed:
            return self._locale.t("errors.not_allowed")
        if self.fix_prs is None:
            return self._locale.t("errors.fixpr_off")
        return await self.fix_prs.approve(value, user_id)


class SlackNotifier:
    """Posts incidents to Slack and receives button presses over Socket Mode (outbound connection only)."""

    def __init__(
        self,
        bot_token: SecretStr,
        app_token: SecretStr,
        alerts_channel: str,
        ops_channel: str,
        actions: ButtonActions,
        oncall_text: Callable[[], str],
        *,
        locale: Locale,
        with_analysis: bool = False,
    ) -> None:
        self._locale = locale
        self._app = AsyncApp(token=bot_token.get_secret_value())
        self._handler = AsyncSocketModeHandler(self._app, app_token.get_secret_value())
        self._alerts_channel = alerts_channel
        self._ops_channel = ops_channel
        self._actions = actions
        self._oncall_text = oncall_text
        self._with_analysis = with_analysis
        self._app.command("/oncall")(self._on_oncall)
        for action_id in ("incident_ack", *_ANALYZE, *_SILENCE):
            self._app.action(action_id)(self._on_button)
        self._app.action(REBOOT_ACTION)(self._on_reboot_button)
        self._app.action(RUNBOOK_ACTION)(self._on_runbook_button)
        self._app.action(FIXPR_ACTION)(self._on_fixpr_button)
        for action_id in FEEDBACK_ACTIONS:
            self._app.action(action_id)(self._on_feedback_button)

    async def start(self) -> None:
        await self._handler.connect_async()  # type: ignore[no-untyped-call]

    async def stop(self) -> None:
        await self._handler.close_async()  # type: ignore[no-untyped-call]

    async def _on_oncall(self, ack: Any) -> None:
        await ack(self._oncall_text())

    async def _on_button(self, ack: Any, body: dict[str, Any], respond: Any) -> None:
        await ack()
        action = body["actions"][0]
        error = await self._actions.handle(body["user"]["id"], action["action_id"], int(action["value"]))
        if error:
            await respond(text=error, response_type="ephemeral", replace_original=False)
        elif action["action_id"] in _ANALYZE:
            text = self._locale.t("slack.analysis_running")
            await respond(text=text, response_type="ephemeral", replace_original=False)

    async def _on_reboot_button(self, ack: Any, body: dict[str, Any], respond: Any) -> None:
        await ack()
        error = await self._actions.handle_reboot(body["user"]["id"], body["actions"][0]["value"])
        if error:
            await respond(text=error, response_type="ephemeral", replace_original=False)

    async def _on_runbook_button(self, ack: Any, body: dict[str, Any], respond: Any) -> None:
        await ack()
        error = await self._actions.handle_runbook(body["user"]["id"], body["actions"][0]["value"])
        if error:
            await respond(text=error, response_type="ephemeral", replace_original=False)

    async def _on_feedback_button(self, ack: Any, body: dict[str, Any], respond: Any) -> None:
        await ack()
        action = body["actions"][0]
        user = body["user"]["id"]
        error = await self._actions.handle_feedback(user, action["action_id"], action["value"])
        if error:
            await respond(text=error, response_type="ephemeral", replace_original=False)
        else:  # the buttons give way to the verdict, so the question is not answered twice by accident
            key = "marked_helpful" if FEEDBACK_ACTIONS[action["action_id"]] == "helpful" else "marked_not_helpful"
            await respond(text=self._locale.t(f"slack.feedback.{key}", user=user), replace_original=True)

    async def _on_fixpr_button(self, ack: Any, body: dict[str, Any], respond: Any) -> None:
        await ack()
        error = await self._actions.handle_fixpr(body["user"]["id"], body["actions"][0]["value"])
        if error:
            await respond(text=error, response_type="ephemeral", replace_original=False)

    async def post_incident(self, view: IncidentView) -> tuple[str, str]:
        response = await self._app.client.chat_postMessage(
            channel=self._alerts_channel,
            text=fallback_text(self._locale, view),
            blocks=incident_blocks(self._locale, view, analyze_button=self._with_analysis),
        )
        return str(response["channel"]), str(response["ts"])

    async def update_incident(self, view: IncidentView, channel: str, ts: str) -> None:
        await self._app.client.chat_update(
            channel=channel,
            ts=ts,
            text=fallback_text(self._locale, view),
            blocks=incident_blocks(self._locale, view, analyze_button=self._with_analysis),
        )

    async def reply(self, channel: str, ts: str, text: str) -> None:
        await self._app.client.chat_postMessage(channel=channel, thread_ts=ts, text=text)

    async def reply_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> str:
        response = await self._app.client.chat_postMessage(channel=channel, thread_ts=ts, text=text, blocks=blocks)
        return str(response["ts"])

    async def post_ops(self, text: str) -> None:
        await self._app.client.chat_postMessage(channel=self._ops_channel, text=text)

    async def post_ops_message(self, text: str, blocks: list[dict[str, Any]]) -> tuple[str, str]:
        response = await self._app.client.chat_postMessage(channel=self._ops_channel, text=text, blocks=blocks)
        return str(response["channel"]), str(response["ts"])

    async def update_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> None:
        await self._app.client.chat_update(channel=channel, ts=ts, text=text, blocks=blocks)


class LogNotifier:
    """Stands in for Slack and the pager when no tokens are configured (local development)."""

    async def post_incident(self, view: IncidentView) -> tuple[str, str]:
        log.info("[chat] new incident #%s %s %s: %s", view.id, view.severity, view.title, view.summary)
        return "log", str(view.id)

    async def update_incident(self, view: IncidentView, channel: str, ts: str) -> None:
        log.info("[chat] incident #%s now %s", view.id, view.status)

    async def reply(self, channel: str, ts: str, text: str) -> None:
        log.info("[chat] reply on %s: %s", ts, text)

    async def reply_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> str:
        log.info("[chat] reply message on %s: %s", ts, text)
        return "0"

    async def post_ops(self, text: str) -> None:
        log.info("[chat] ops: %s", text)

    async def post_ops_message(self, text: str, blocks: list[dict[str, Any]]) -> tuple[str, str]:
        log.info("[chat] ops message: %s", text)
        return "log", "0"

    async def update_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> None:
        log.info("[chat] message %s now: %s", ts, text)

    async def page(self, person: Person, view: IncidentView, *, escalated: bool) -> None:
        log.info("[pager] %s -> %s (escalated=%s)", view.title, person.name, escalated)
