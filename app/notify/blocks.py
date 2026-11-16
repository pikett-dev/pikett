"""Slack Block Kit messages, in the language of the locale."""

from typing import Any

from app.i18n import Locale
from app.incidents.memory import KnownSolution
from app.models import IncidentAnalysis
from app.notify.base import IncidentView

_ICON = {"P1": ":red_circle:", "P2": ":large_orange_circle:", "P3": ":large_yellow_circle:"}


def approval_blocks(
    locale: Locale, text: str, label: str, action_id: str, value: str, confirm_title: str, confirm_text: str
) -> list[dict[str, Any]]:
    """A message with one primary approval button that asks for a confirmation first."""
    button = {
        "type": "button",
        "text": {"type": "plain_text", "text": label},
        "style": "primary",
        "action_id": action_id,
        "value": value,
        "confirm": {
            "title": {"type": "plain_text", "text": confirm_title},
            "text": {"type": "plain_text", "text": confirm_text},
            "confirm": {"type": "plain_text", "text": locale.t("slack.approve")},
            "deny": {"type": "plain_text", "text": locale.t("slack.cancel")},
        },
    }
    return [{"type": "section", "text": {"type": "mrkdwn", "text": text}}, {"type": "actions", "elements": [button]}]


def fallback_text(locale: Locale, view: IncidentView) -> str:
    state = locale.t("slack.state.resolved" if view.status == "resolved" else "slack.state.open")
    return f"{view.severity} {view.title} ({state})"


FEEDBACK_HELPFUL = "analysis_helpful"
FEEDBACK_NOT_HELPFUL = "analysis_not_helpful"
FEEDBACK_ACTIONS = {FEEDBACK_HELPFUL: "helpful", FEEDBACK_NOT_HELPFUL: "not_helpful"}

ANALYZE_ACTION = "incident_analyze"  # Sonnet
ANALYZE_DEEP_ACTION = "incident_analyze_deep"  # Opus


def incident_blocks(locale: Locale, view: IncidentView, *, analyze_button: bool = False) -> list[dict[str, Any]]:
    resolved = view.status == "resolved"
    head = f"{':white_check_mark:' if resolved else _ICON.get(view.severity, '')} *{view.severity} {view.title}*"
    lines = [view.summary] if view.summary else []
    since = locale.t("slack.incident.since", at=locale.clock(view.started_at))
    if view.resolved_at:
        since += locale.t("slack.incident.resolved_at", at=locale.clock(view.resolved_at))
    lines.append(since)
    if not resolved and view.oncall_slack_id:
        lines.append(locale.t("slack.incident.oncall", id=view.oncall_slack_id))
    if view.acked_by:
        lines.append(locale.t("slack.incident.acked", id=view.acked_by))
    if view.silenced_until and not resolved:
        lines.append(locale.t("slack.incident.silenced", at=locale.clock(view.silenced_until)))

    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": head + "\n" + "\n".join(lines)}}
    ]

    elements: list[dict[str, Any]] = []
    if not resolved:
        if not view.acked_by:
            elements.append(_button(locale.t("slack.button.ack"), "incident_ack", view.id, primary=True))
        elements.append(_button(locale.t("slack.button.silence_1h"), "incident_silence_1h", view.id))
        elements.append(_button(locale.t("slack.button.silence_24h"), "incident_silence_24h", view.id))
        if analyze_button:
            elements.append(_button(locale.t("slack.button.analyze"), ANALYZE_ACTION, view.id))
            elements.append(_button(locale.t("slack.button.analyze_deep"), ANALYZE_DEEP_ACTION, view.id))
    elements.append(
        {"type": "button", "text": {"type": "plain_text", "text": locale.t("slack.button.details")}, "url": view.url}
    )
    blocks.append({"type": "actions", "elements": elements})
    return blocks


def _button(label: str, action_id: str, incident_id: int, *, primary: bool = False) -> dict[str, Any]:
    button = {
        "type": "button",
        "text": {"type": "plain_text", "text": label},
        "action_id": action_id,
        "value": str(incident_id),
    }
    if primary:
        button["style"] = "primary"
    return button


def evidence_note(locale: Locale, run: IncidentAnalysis) -> str:
    """What to say about the evidence of a finished analysis, or "" when all is in order. Used by Slack and the page."""
    if not run.verified:
        return locale.t("analysis.evidence.unverified")
    if run.dropped_evidence:
        return locale.t("analysis.evidence.dropped", n=run.dropped_evidence)
    return ""


def escape(text: str) -> str:
    """Slack's escaping: text from logs, runners or a model must not become a mention or a link. Slack reads `<...>`
    as one, and the masker's placeholders (`<EMAIL_1>`) must stay text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def feedback_question(locale: Locale) -> str:
    return locale.t("slack.feedback.question")


def feedback_blocks(locale: Locale, analysis_id: int) -> list[dict[str, Any]]:
    """The question under an analysis, with its two buttons; the button value is the analysis id."""
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": feedback_question(locale)}},
        {
            "type": "actions",
            "elements": [
                _button(locale.t("slack.button.helpful"), FEEDBACK_HELPFUL, analysis_id),
                _button(locale.t("slack.button.not_helpful"), FEEDBACK_NOT_HELPFUL, analysis_id),
            ],
        },
    ]


def known_solution_text(locale: Locale, solution: KnownSolution, incident_url: str, earlier_url: str, at: str) -> str:
    """The reply for an incident that has happened before: the solution people marked helpful, no new analysis."""
    a = solution.analysis
    return "\n".join(
        [
            locale.t("slack.known.head", url=earlier_url, id=solution.incident_id, at=at),
            locale.t("slack.known.cause", text=escape(str(a.get("cause") or "-"))),
            locale.t("slack.known.now", text=escape(str(a.get("immediate_action") or "-"))),
            locale.t("slack.known.tail", url=incident_url),
        ]
    )


def analysis_text(locale: Locale, run: IncidentAnalysis, url: str) -> str:
    """The reply in the incident thread: the analysis, its evidence and a warning where the evidence is missing."""
    if run.analysis is None:
        reason = escape(run.error or locale.t("slack.analysis.unknown_error"))
        return locale.t("slack.analysis.failed", reason=reason, url=url)
    a = run.analysis
    cost = locale.decimal(float(run.cost_usd or 0), 2)
    confidence = locale.label("common.confidence", a["confidence"])
    lines = [
        locale.t("slack.analysis.head", model=run.model, cost=cost),
        locale.t("slack.analysis.summary", text=escape(a["summary"])),
        locale.t("slack.analysis.cause", confidence=confidence, text=escape(a["cause"])),
    ]
    # A backtick in a quote would end the code span.
    lines += [f"• `{escape(e['quote']).replace('`', 'ˋ')}` ({escape(e['source'])})" for e in a.get("evidence", [])]
    if note := evidence_note(locale, run):
        lines.append(f":warning: {note}" if not run.verified else f"_{note}_")
    lines += [
        locale.t("slack.analysis.immediate", text=escape(a["immediate_action"])),
        locale.t("slack.analysis.fix", text=escape(a["fix_suggestion"])),
        locale.t("slack.analysis.details", url=url),
    ]
    return "\n".join(lines)
