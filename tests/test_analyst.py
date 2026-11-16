import asyncio
import json

import pytest

from app.agent.analysis import SUBMIT_TOOL, Analysis, verify_evidence
from app.agent.analyst import Analyst, IncidentContext
from app.agent.errors import SourceError
from app.agent.llm import LlmError, MaskedLlm, ToolCall
from app.agent.masking import Masker
from app.agent.ports import Sources
from app.agent.pricing import cost_usd
from app.agent.tools import build_registry
from app.agent.usage import LlmUsage
from tests.fakes import JWT, NOW, FakeLogs, FakeMetrics, FakeTraces, ScriptedLlm, llm_reply

LOG_LINE = "HikariPool-1 - Connection is not available, request timed out after 30000ms"
INCIDENT = IncidentContext(
    title="SlowRoute", severity="P2", summary="GET /api/v1/me is slow", started_at=NOW, labels={"service": "core"}
)


def submit(**overrides):
    args = {
        "summary": "Der Connection-Pool von core ist erschöpft.",
        "cause": "Alle Datenbankverbindungen sind belegt.",
        "evidence": [{"quote": "Connection is not available, request timed out after 30000ms", "source": "query_logs"}],
        "confidence": "medium",
        "affected": "core, alle Endpunkte mit Datenbankzugriff",
        "immediate_action": "core neu starten",
        "runbook": "",
        "runbook_host": "",
        "runbook_application": "",
        "fix_suggestion": "Pool-Größe und lange Transaktionen prüfen",
        "risk": "Ein Neustart unterbricht laufende Anfragen",
    }
    return ToolCall("toolu_submit", "submit_analysis", {**args, **overrides})


def sources(logs=None) -> Sources:
    return Sources(logs or FakeLogs([{"_msg": LOG_LINE}]), FakeMetrics(), FakeTraces())


def analyst(llm, logs=None, **overrides):
    settings = {"model": "claude-opus-5-5", "max_iterations": 12, "max_tokens": 8000, "timeout_seconds": 30}
    registry_for = lambda masker: build_registry(sources(logs), masker, clock=lambda: NOW)  # noqa: E731
    return Analyst(llm, registry_for, **{**settings, **overrides})


def search_logs(id_="toolu_1"):
    return ToolCall(id_, "query_logs", {"query": "error"})


async def test_a_backed_analysis_is_returned_with_cost_and_counts():
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(submit())])
    outcome = await analyst(llm).run(INCIDENT)
    assert outcome.error is None and outcome.analysis is not None
    assert outcome.verified and outcome.dropped_evidence == 0
    assert (outcome.iterations, outcome.tool_calls) == (2, 1)
    usage = LlmUsage(input_tokens=2000, output_tokens=400, cache_read_tokens=6000)
    assert outcome.usage == usage and outcome.cost_usd == pytest.approx(cost_usd("claude-opus-5-5", usage))
    followup = llm.calls[1]["messages"][-1]["content"][0]  # the tool result went back in a tool_result block
    assert followup["type"] == "tool_result" and LOG_LINE in followup["content"] and followup["is_error"] is False


async def test_evidence_that_no_tool_returned_is_dropped_and_confidence_falls():
    invented = {"quote": "OutOfMemoryError: Java heap space", "source": "query_logs"}
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(submit(evidence=[invented], confidence="high"))])
    outcome = await analyst(llm).run(INCIDENT)
    assert outcome.analysis is not None
    assert outcome.verified is False and outcome.dropped_evidence == 1
    assert outcome.analysis.evidence == [] and outcome.analysis.confidence == "low"


def test_a_quote_counts_only_for_the_tool_it_names_and_survives_json_escaping():
    analysis = Analysis.model_validate(submit().input)
    results = [
        (
            "query_logs",
            '{"rows": [{"_msg": "said \\"no\\"\\n  Connection is not available,  request timed out after 30000ms"}]}',
        )
    ]
    assert verify_evidence(analysis, results)[1] == 0
    other_tool = [("get_trace", results[0][1])]  # the quote exists, but not in a result of the tool it claims
    kept, dropped = verify_evidence(analysis, other_tool)
    assert dropped == 1 and kept.evidence == [] and kept.confidence == "low"


async def test_nothing_unmasked_reaches_the_model():
    incident = IncidentContext(
        title="Login failures for anna@example.at", severity="P1", summary=f"token {JWT} rejected", started_at=NOW
    )
    logs = FakeLogs([{"_msg": "login failed for ben@example.at"}])
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(submit(evidence=[]))])
    await analyst(llm, logs=logs).run(incident)
    sent = json.dumps(llm.calls)
    assert "example.at" not in sent and "eyJ" not in sent
    assert "<EMAIL_1>" in sent and "<EMAIL_2>" in sent  # stable placeholders across incident text and tool results


async def test_the_port_wrapper_masks_user_turns_and_leaves_model_turns_alone():
    llm = ScriptedLlm([llm_reply(submit(evidence=[]))])
    raw = [{"type": "tool_use", "id": "t1", "name": "x", "input": {"who": "anna@example.at"}}]
    messages = [
        {"role": "user", "content": "alert for anna@example.at"},
        {"role": "assistant", "content": raw},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ben@example.at"}]},
    ]
    await MaskedLlm(llm, Masker()).complete(model="m", system="s", tools=[], messages=messages, max_tokens=10)
    sent = llm.calls[0]["messages"]
    assert sent[0]["content"] == "alert for <EMAIL_1>"
    assert sent[1]["content"] == raw  # unchanged: the model's own turn is sent back as received
    assert sent[2]["content"][0]["content"] == "<EMAIL_2>"


async def test_an_invalid_submission_is_sent_back_and_can_be_fixed():
    broken = ToolCall("toolu_bad", "submit_analysis", {"summary": "x"})
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(broken), llm_reply(submit())])
    outcome = await analyst(llm).run(INCIDENT)
    assert outcome.analysis is not None and outcome.iterations == 3
    error_block = llm.calls[2]["messages"][-1]["content"][0]
    assert error_block["is_error"] is True and "cause" in error_block["content"]


async def test_parallel_tool_calls_all_get_a_result_in_the_order_of_the_calls():
    calls = (ToolCall("a", "query_logs", {"query": "x"}), ToolCall("b", "list_trace_services", {}))
    llm = ScriptedLlm([llm_reply(*calls), llm_reply(submit(evidence=[]))])
    outcome = await analyst(llm).run(INCIDENT)
    assert outcome.tool_calls == 2
    assert [b["tool_use_id"] for b in llm.calls[1]["messages"][-1]["content"]] == ["a", "b"]


async def test_a_model_api_failure_is_an_outcome_not_an_exception_and_keeps_the_cost_so_far():
    llm = ScriptedLlm([llm_reply(search_logs()), LlmError("model API call failed (RateLimitError, 429)")])
    outcome = await analyst(llm).run(INCIDENT)
    assert outcome.analysis is None and "RateLimitError" in (outcome.error or "")
    assert outcome.cost_usd > 0


async def test_the_iteration_limit_stops_a_runaway_loop():
    llm = ScriptedLlm([llm_reply(search_logs(f"t{i}")) for i in range(3)])
    outcome = await analyst(llm, max_iterations=3).run(INCIDENT)
    assert outcome.analysis is None and "after 3 model calls" in (outcome.error or "")
    assert outcome.cost_usd > 0 and not llm.replies


async def test_a_timeout_ends_the_run_and_still_reports_what_was_spent():
    class SlowSecondCall(ScriptedLlm):
        async def complete(self, **kwargs):
            if self.calls:
                await asyncio.sleep(5)
            return await super().complete(**kwargs)

    outcome = await analyst(SlowSecondCall([llm_reply(search_logs())]), timeout_seconds=0.1).run(INCIDENT)
    assert outcome.analysis is None and "timed out" in (outcome.error or "")
    assert outcome.cost_usd > 0 and outcome.iterations == 2


async def test_a_model_that_never_submits_is_nudged_once_then_given_up_on():
    llm = ScriptedLlm([llm_reply(text="I think it is the database."), llm_reply(text="Still the database.")])
    outcome = await analyst(llm).run(INCIDENT)
    assert "without submitting" in (outcome.error or "")
    assert "submit_analysis" in llm.calls[1]["messages"][-1]["content"]


@pytest.mark.parametrize("stop", ["max_tokens", "refusal"])
async def test_an_early_stop_is_an_error(stop):
    outcome = await analyst(ScriptedLlm([llm_reply(search_logs(), stop=stop)])).run(INCIDENT)
    assert outcome.analysis is None and stop in (outcome.error or "")


async def test_an_unexpected_crash_is_contained():
    def broken_registry(masker):
        raise RuntimeError("boom with anna@example.at")

    outcome = await Analyst(
        ScriptedLlm([]), broken_registry, model="claude-opus-5-5", max_iterations=3, max_tokens=100, timeout_seconds=5
    ).run(INCIDENT)
    assert outcome.analysis is None and "example.at" not in (outcome.error or "")


async def test_tool_errors_go_back_to_the_model_and_the_run_continues():
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(submit(evidence=[]))])
    outcome = await analyst(llm, logs=FakeLogs(error=SourceError("VictoriaLogs returned 400"))).run(INCIDENT)
    assert outcome.analysis is not None
    block = llm.calls[1]["messages"][-1]["content"][0]
    assert block["is_error"] is True and "400" in block["content"]


async def test_the_model_is_offered_the_registry_tools_and_the_submit_tool_only():
    llm = ScriptedLlm([llm_reply(submit(evidence=[]))])
    await analyst(llm).run(INCIDENT)
    expected = {d["name"] for d in build_registry(sources(), Masker()).definitions()} | {"submit_analysis"}
    assert {t["name"] for t in llm.calls[0]["tools"]} == expected
    assert llm.calls[0]["model"] == "claude-opus-5-5"


def test_the_submit_schema_matches_the_model_including_the_limits():
    hand = SUBMIT_TOOL["input_schema"]
    model = Analysis.model_json_schema()
    assert set(hand["properties"]) == set(model["properties"]) == set(hand["required"])
    limits = ("maxLength", "minLength", "maxItems", "enum")
    for name, spec in model["properties"].items():
        for key in limits:
            assert hand["properties"][name].get(key) == spec.get(key), (name, key)
    for name, spec in model["$defs"]["Evidence"]["properties"].items():
        for key in limits:
            assert hand["properties"]["evidence"]["items"]["properties"][name].get(key) == spec.get(key), (name, key)


def test_quotes_match_decoded_json_strings_not_their_escapes():
    analysis = Analysis.model_validate(
        submit(evidence=[{"quote": "Verbindung für Pool fehlgeschlagen", "source": "query_logs"}]).input
    )
    escaped = '{"rows": [{"_msg": "Fehler: Verbindung f\\u00fcr Pool fehlgeschlagen"}]}'
    assert verify_evidence(analysis, [("query_logs", escaped)])[1] == 0


async def test_an_error_result_is_no_evidence():
    quote = "the tool failed unexpectedly; try a different query"
    claim = {"quote": quote, "source": "query_logs"}
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(submit(evidence=[claim]))])
    outcome = await analyst(llm, logs=FakeLogs(error=KeyError("boom"))).run(INCIDENT)
    assert outcome.analysis is not None and outcome.verified is False and outcome.dropped_evidence == 1


async def test_a_submission_in_the_same_reply_as_lookups_skips_the_lookups():
    logs = FakeLogs([{"_msg": LOG_LINE}])
    llm = ScriptedLlm([llm_reply(search_logs(), submit())])
    outcome = await analyst(llm, logs=logs).run(INCIDENT)
    assert outcome.tool_calls == 0 and logs.calls == []
    assert outcome.verified is False  # the quote is not backed: the lookup it relies on never ran


async def test_an_empty_model_reply_is_an_error_not_a_rejected_request():
    llm = ScriptedLlm([llm_reply(text="", stop="end_turn")])
    outcome = await analyst(llm).run(INCIDENT)
    assert "empty reply" in (outcome.error or "")


async def test_the_long_prompt_price_applies_per_request_not_to_the_sum_of_a_run():
    usage = LlmUsage(input_tokens=60_000, output_tokens=1_000)  # under 100k each, 180k together
    llm = ScriptedLlm(
        [
            llm_reply(search_logs(), usage=usage),
            llm_reply(search_logs("b"), usage=usage),
            llm_reply(submit(evidence=[]), usage=usage),
        ]
    )
    outcome = await analyst(llm, model="claude-haiku-5-5").run(INCIDENT)
    assert outcome.cost_usd == pytest.approx(3 * cost_usd("claude-haiku-5-5", usage))
    assert outcome.cost_usd < cost_usd("claude-haiku-5-5", outcome.usage)  # the summed usage would hit the long tier


async def test_the_port_wrapper_masks_text_blocks_and_list_content_and_rejects_unknown_blocks():
    llm = ScriptedLlm([llm_reply(submit(evidence=[]))])
    wrapped = MaskedLlm(llm, Masker())
    turn = [
        {
            "type": "tool_result",
            "tool_use_id": "toolu_0123456789abcdefghijklmnopqrstuv",
            "content": [{"type": "text", "text": "ben@example.at"}],
        },
        {"type": "text", "text": "hint for anna@example.at"},
    ]
    await wrapped.complete(model="m", system="s", tools=[], messages=[{"role": "user", "content": turn}], max_tokens=10)
    sent = llm.calls[0]["messages"][0]["content"]
    assert sent[0]["content"][0]["text"] == "<EMAIL_1>" and sent[1]["text"] == "hint for <EMAIL_2>"
    assert sent[0]["tool_use_id"] == turn[0]["tool_use_id"]  # the pairing id is never masked
    bad = [{"role": "user", "content": [{"type": "image", "source": {}}]}]
    with pytest.raises(ValueError, match="unsupported block type"):
        await wrapped.complete(model="m", system="s", tools=[], messages=bad, max_tokens=10)


async def test_the_model_is_asked_to_submit_on_its_last_call():
    llm = ScriptedLlm([llm_reply(search_logs()), llm_reply(search_logs("b"))])
    await analyst(llm, max_iterations=2).run(INCIDENT)
    hint = llm.calls[1]["messages"][-1]["content"][-1]
    assert hint["type"] == "text" and "last call" in hint["text"]


@pytest.mark.parametrize("stop", ["model_context_window_exceeded", "pause_turn"])
async def test_any_unexpected_stop_reason_is_an_error(stop):
    outcome = await analyst(ScriptedLlm([llm_reply(text="partial", stop=stop)])).run(INCIDENT)
    assert stop in (outcome.error or "")


async def test_a_crash_is_logged_without_the_raw_message(caplog):
    def broken_registry(masker):
        raise RuntimeError("boom with anna@example.at")

    broken = Analyst(
        ScriptedLlm([]), broken_registry, model="claude-opus-5-5", max_iterations=3, max_tokens=100, timeout_seconds=5
    )
    with caplog.at_level("ERROR"):
        await broken.run(INCIDENT)
    assert "RuntimeError" in caplog.text and "example.at" not in caplog.text
