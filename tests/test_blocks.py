from datetime import timedelta

from app.notify.blocks import fallback_text, incident_blocks
from tests.fakes import EN, START, view


def buttons(blocks) -> dict[str, str]:
    return {e["text"]["text"]: e.get("action_id", "link") for e in blocks[1]["elements"]}


def test_open_incident_offers_ack_silence_and_details():
    blocks = incident_blocks(EN, view())

    assert buttons(blocks) == {
        "Take over": "incident_ack",
        "Mute 1 h": "incident_silence_1h",
        "Mute 24 h": "incident_silence_24h",
        "Details": "link",
    }
    assert "<@U_ALICE>" in blocks[0]["text"]["text"]
    assert all(e["value"] == "7" for e in blocks[1]["elements"] if "action_id" in e)


def test_acknowledged_incident_drops_the_ack_button_and_names_the_person():
    blocks = incident_blocks(EN, view(acked_by="U_BOB"))

    assert "Take over" not in buttons(blocks)
    assert "Taken over by <@U_BOB>" in blocks[0]["text"]["text"]


def test_resolved_incident_only_keeps_the_details_link():
    blocks = incident_blocks(EN, view(status="resolved", resolved_at=START + timedelta(minutes=5)))

    assert buttons(blocks) == {"Details": "link"}
    assert "resolved" in blocks[0]["text"]["text"]
    assert fallback_text(EN, view(status="resolved")) == "P1 AppServerSilent (resolved)"


def test_the_analyze_button_is_only_there_for_open_incidents_when_the_agent_is_on():
    def actions(view_, **kwargs):
        elements = incident_blocks(EN, view_, **kwargs)[-1]["elements"]
        return [e.get("action_id") for e in elements]

    assert "incident_analyze" not in actions(view())
    assert "incident_analyze" in actions(view(), analyze_button=True)
    assert "incident_analyze" not in actions(view(status="resolved"), analyze_button=True)
    assert "incident_analyze_deep" not in actions(view())
    assert "incident_analyze_deep" in actions(view(), analyze_button=True)
    assert "incident_analyze_deep" not in actions(view(status="resolved"), analyze_button=True)


def _run(**fields):
    from app.models import IncidentAnalysis

    base = {"status": "done", "model": "claude-opus-5-5", "cost_usd": 0.123, "verified": False, "dropped_evidence": 2}
    return IncidentAnalysis(**{**base, **fields})


def test_the_analysis_text_keeps_placeholders_as_text_and_warns_without_evidence():
    from app.notify.blocks import analysis_text

    analysis = {
        "summary": "Login fails for <EMAIL_1>",
        "cause": "Pool & Timeout",
        "confidence": "low",
        "evidence": [],
        "affected": "core",
        "immediate_action": "Restart",
        "fix_suggestion": "Increase the pool",
        "risk": "brief",
    }
    text = analysis_text(EN, _run(analysis=analysis), "http://ops.test/incidents/7")
    assert "&lt;EMAIL_1&gt;" in text and "<EMAIL_1>" not in text and "Pool &amp; Timeout" in text
    assert (
        "0.12 USD" in text
        and "confidence low" in text
        and ":warning:" in text
        and "Read the cause with caution" in text
    )
    backed = {**analysis, "evidence": [{"quote": "boom", "source": "t"}]}
    text = analysis_text(EN, _run(analysis=backed, verified=True), "u")
    assert "2 quote(s) without evidence" in text and "with caution" not in text and "boom" in text
    failed = analysis_text(EN, _run(analysis=None, error="Timeout <5s>"), "u")
    assert failed.startswith(":warning:") and "&lt;5s&gt;" in failed


def test_the_evidence_note_is_empty_when_all_is_in_order():
    from app.notify.blocks import evidence_note

    assert evidence_note(EN, _run(analysis={}, verified=True, dropped_evidence=0)) == ""


def test_a_backtick_in_a_quote_does_not_end_the_code_span():
    from app.notify.blocks import analysis_text

    analysis = {
        "summary": "s",
        "cause": "c",
        "confidence": "low",
        "evidence": [{"quote": "select `name` from owners", "source": "query_logs"}],
        "affected": "-",
        "immediate_action": "-",
        "fix_suggestion": "-",
        "risk": "-",
    }
    line = next(x for x in analysis_text(EN, _run(analysis=analysis, verified=True), "u").splitlines() if "select" in x)
    assert line.count("`") == 2 and "ˋname" in line
