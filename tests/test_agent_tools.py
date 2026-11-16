import json
from typing import Any

import pytest

from app.agent.errors import SourceError
from app.agent.masking import Masker
from app.agent.ports import Sources
from app.agent.tools import build_registry
from tests.fakes import JWT, NOW, FakeLogs, FakeMetrics, FakeTraces

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"


def span(span_id: str, parent: str | None, start: int, duration: int, tags=None, process="p1", logs=None):
    return {
        "spanID": span_id,
        "operationName": f"op-{span_id}",
        "startTime": start,
        "duration": duration,
        "processID": process,
        "references": [{"refType": "CHILD_OF", "spanID": parent}] if parent else [],
        "tags": [{"key": k, "type": "string", "value": v} for k, v in (tags or {}).items()],
        "logs": logs or [],
    }


def trace(spans: list[dict[str, Any]]) -> dict[str, Any]:
    return {"traceID": TRACE_ID, "spans": spans, "processes": {"p1": {"serviceName": "core", "tags": []}}}


def registry(logs=None, metrics=None, traces=None, **kwargs):
    sources = Sources(logs or FakeLogs(), metrics or FakeMetrics(), traces or FakeTraces())
    return build_registry(sources, Masker(), clock=lambda: NOW, **kwargs)


async def test_every_tool_masks_pii_in_its_result():
    pii_trace = trace(
        [
            span(
                "s1",
                None,
                1_000_000,
                5_000,
                {"http.url": "/u?mail=anna@example.at", "exception": f"Bearer-less token {JWT}", "error": "true"},
                logs=[{"timestamp": 1, "fields": [{"key": "message", "value": "failed for ben@example.at"}]}],
            )
        ]
    )
    reg = registry(
        logs=FakeLogs([{"_msg": "login anna@example.at"}]),
        metrics=FakeMetrics({"resultType": "vector", "result": [{"metric": {"user": "anna@example.at"}}]}),
        traces=FakeTraces([pii_trace]),
    )
    calls = [
        ("query_logs", {"query": "login"}),
        ("query_metrics", {"query": "up"}),
        ("query_metrics_range", {"query": "up"}),
        ("query_traces", {"service": "core"}),
        ("get_trace", {"trace_id": TRACE_ID}),
    ]
    for name, args in calls:
        result = await reg.call(name, args)
        assert not result.is_error, (name, result.text)
        assert "example.at" not in result.text, name
        assert "eyJ" not in result.text, name


async def test_source_errors_are_returned_masked_and_flagged():
    reg = registry(logs=FakeLogs(error=SourceError("VictoriaLogs returned 400 for anna@example.at")))
    result = await reg.call("query_logs", {"query": "x"})
    assert result.is_error
    assert "example.at" not in result.text
    assert "400" in result.text


async def test_unknown_tool_and_missing_arguments_are_errors_not_exceptions():
    reg = registry()
    assert (await reg.call("drop_database", {})).is_error
    missing = await reg.call("query_logs", {})
    assert missing.is_error and "'query' is required" in missing.text


async def test_large_results_are_trimmed_to_valid_json():
    rows = [{"_msg": "x" * 300, "n": i} for i in range(200)]
    result = await registry(logs=FakeLogs(rows)).call("query_logs", {"query": "x", "limit": 200})
    body = json.loads(result.text)  # still valid JSON, not cut in the middle
    assert body["truncated_for_size"] is True
    assert 0 < len(body["rows"]) < 200
    assert len(result.text) <= 20_000


async def test_long_strings_are_clipped_per_value():
    result = await registry(logs=FakeLogs([{"_msg": "y" * 5000}])).call("query_logs", {"query": "x"})
    row = json.loads(result.text)["rows"][0]
    assert len(row["_msg"]) < 600


@pytest.mark.parametrize("limit", [0, 201, "5", True, 1.5])
async def test_log_limit_is_validated(limit):
    result = await registry().call("query_logs", {"query": "x", "limit": limit})
    assert result.is_error and "'limit'" in result.text


async def test_log_window_defaults_and_bounds():
    logs = FakeLogs()
    reg = registry(logs=logs)
    await reg.call("query_logs", {"query": "x"})
    assert logs.calls[0][2] == NOW
    assert (NOW - logs.calls[0][1]).total_seconds() == 3600
    too_long = await reg.call("query_logs", {"query": "x", "start": "now-2d"})
    assert too_long.is_error and "longer" in too_long.text
    bad = await reg.call("query_logs", {"query": "x", "start": "last week"})
    assert bad.is_error and "cannot parse" in bad.text


async def test_metrics_series_are_capped_and_range_points_are_bounded():
    many = {"resultType": "vector", "result": [{"metric": {"i": str(i)}} for i in range(80)]}
    reg = registry(metrics=FakeMetrics(many))
    body = json.loads((await reg.call("query_metrics", {"query": "up"})).text)
    assert body["series_total"] == 80 and len(body["series"]) == 50 and body["truncated"] is True
    too_dense = await reg.call("query_metrics_range", {"query": "up", "start": "now-6h", "step": "1s"})
    assert too_dense.is_error and "points" in too_dense.text
    ok = await reg.call("query_metrics_range", {"query": "up", "start": "now-6h", "step": "1m"})
    assert not ok.is_error


async def test_query_traces_filters_and_summarises():
    slow = trace(
        [
            span("root", None, 1_794_509_849_953_000, 1_224_788, {"error": "unset"}),
            span("child", "root", 1_794_509_849_954_000, 1_000_000, {"error": "true"}),
        ]
    )
    traces = FakeTraces([slow])
    reg = registry(traces=traces)
    result = await reg.call(
        "query_traces", {"service": "core", "errors_only": True, "min_duration": "500ms", "operation": "GET /x"}
    )
    assert traces.calls[0] == ("core", 10, "GET /x", {"error": "true"}, "500ms")
    summary = json.loads(result.text)["traces"][0]
    assert summary["root"] == "core: op-root"
    assert summary["duration_ms"] == 1224.8
    assert summary["spans"] == 2 and summary["error_spans"] == 1


@pytest.mark.parametrize(
    "args", [{"service": "core", "min_duration": "slow"}, {"service": "core", "errors_only": "yes"}]
)
async def test_query_traces_validates_inputs(args):
    assert (await registry().call("query_traces", args)).is_error


async def test_get_trace_validates_id_and_reports_missing():
    reg = registry()
    assert (await reg.call("get_trace", {"trace_id": "not-hex"})).is_error
    missing = await reg.call("get_trace", {"trace_id": TRACE_ID})
    assert missing.is_error and "not found" in missing.text


async def test_get_trace_returns_parent_links_offsets_and_selected_tags():
    t = trace(
        [
            span("b", "a", 2_000_000, 500, {"uri": "/x", "noise": "drop-me"}),
            span("a", None, 1_000_000, 3_000_000, {"error": "false"}),
        ]
    )
    body = json.loads((await registry(traces=FakeTraces([t])).call("get_trace", {"trace_id": TRACE_ID})).text)
    first, second = body["spans"]
    assert first["span_id"] == "a" and first["parent_id"] is None and first["offset_ms"] == 0
    assert second["parent_id"] == "a" and second["offset_ms"] == 1000.0
    assert second["tags"] == {"uri": "/x"}
    assert "events" not in first


async def test_big_trace_keeps_error_spans():
    spans = [span("root", None, 1_000, 10, {})]
    spans += [span(f"s{i}", "root", 2_000 + i, 100 + i, {}) for i in range(300)]
    spans.append(span("boom", "root", 9_000, 1, {"error": "true"}))
    body = json.loads(
        (await registry(traces=FakeTraces([trace(spans)])).call("get_trace", {"trace_id": TRACE_ID})).text
    )
    assert body["spans_total"] == 302 and body["spans_shown"] == 60
    assert "boom" in {s["span_id"] for s in body["spans"]}


async def test_definitions_describe_every_tool():
    defs = registry().definitions()
    assert {d["name"] for d in defs} == {
        "query_logs",
        "list_log_sources",
        "log_templates",
        "query_metrics",
        "query_metrics_range",
        "list_trace_services",
        "query_traces",
        "get_trace",
    }
    for d in defs:
        schema = d["input_schema"]
        assert d["description"] and schema["type"] == "object"
        assert set(schema.get("required", [])) <= set(schema["properties"]), d["name"]


async def test_clipping_happens_after_masking_so_a_cut_value_cannot_leak():
    # Clipping first would cut the address after "anna@exa..." and leave a fragment no pattern recognises.
    row = {"_msg": "x" * 490 + " anna@example.at"}
    text = (await registry(logs=FakeLogs([row])).call("query_logs", {"query": "x"})).text
    assert "anna@" not in text and "example" not in text
    assert "<EMAIL_1>" in text


async def test_unexpected_errors_are_masked_and_do_not_escape():
    result = await registry(logs=FakeLogs(error=KeyError("row for anna@example.at"))).call("query_logs", {"query": "x"})
    assert result.is_error
    assert "example.at" not in result.text and "unexpectedly" in result.text


async def test_only_allowlisted_span_tags_reach_the_agent():
    t = trace([span("a", None, 1_000, 5, {"uri": "/x", "db.statement": "select * from owners where mail='a@b.at'"})])
    text = (await registry(traces=FakeTraces([t])).call("get_trace", {"trace_id": TRACE_ID})).text
    assert "/x" in text and "db.statement" not in text and "owners" not in text


@pytest.mark.parametrize("step", ["0s", "0m", "99999999999d"])
async def test_bad_steps_are_input_errors_not_crashes(step):
    result = await registry().call("query_metrics_range", {"query": "up", "step": step})
    assert result.is_error and "unexpectedly" not in result.text


@pytest.mark.parametrize("start", ["now-99999999999d", "now-400d"])
async def test_absurd_relative_times_are_input_errors(start):
    result = await registry().call("query_logs", {"query": "x", "start": start})
    assert result.is_error and "unexpectedly" not in result.text


@pytest.mark.parametrize("at", ["2000-01-01T00:00:00Z", "now-91d", "2030-01-01T00:00:00Z"])
async def test_instant_query_time_must_be_within_retention(at):
    result = await registry().call("query_metrics", {"query": "up", "time": at})
    assert result.is_error and "'time'" in result.text


async def test_trimming_cuts_series_not_points_and_stays_valid_json():
    series = [{"metric": {"i": str(i)}, "values": [[1_700_000_000 + p, "1.5"] for p in range(500)]} for i in range(50)]
    reg = registry(metrics=FakeMetrics({"resultType": "matrix", "result": series}))
    result = await reg.call("query_metrics_range", {"query": "up", "start": "now-6h", "step": "1m"})
    body = json.loads(result.text)
    assert body["truncated_for_size"] is True and body["series_total"] == 50
    assert 0 < len(body["series"]) < 50
    assert all(len(s["values"]) == 500 for s in body["series"])


async def test_output_is_valid_json_even_when_nothing_can_be_trimmed():
    wide = {"result_type": "vector", "result": [{"metric": {f"label{i}": "v" * 400 for i in range(80)}}]}
    reg = registry(metrics=FakeMetrics(wide))
    body = json.loads((await reg.call("query_metrics", {"query": "up"})).text)
    assert body["truncated_for_size"] is True
    assert "partial_json" in body or len(body["series"]) == 1


async def test_only_allowlisted_event_fields_reach_the_agent():
    events = [{"timestamp": 1, "fields": [{"key": "exception.type", "value": "IOException"}]}]
    events[0]["fields"].append({"key": "db.statement", "value": "select * from owners"})
    t = trace([span("a", None, 1_000, 5, {"error": "true"}, logs=events)])
    text = (await registry(traces=FakeTraces([t])).call("get_trace", {"trace_id": TRACE_ID})).text
    assert "IOException" in text and "owners" not in text


async def test_values_the_masker_does_not_know_are_converted_before_masking():
    class Owner:
        def __str__(self) -> str:
            return "anna@example.at"

    async def handler(args):
        return {"set": {"ben@example.at"}, "obj": Owner(), "when": NOW}

    from app.agent.tools.registry import Tool, ToolRegistry

    reg = ToolRegistry([Tool("t", "d", {"type": "object", "properties": {}}, handler)], Masker())
    text = (await reg.call("t", {})).text
    assert "example.at" not in text and "<EMAIL_" in text


async def test_quote_heavy_unsplittable_output_still_fits_the_budget_as_json():
    wide = {"result_type": "vector", "result": [{"metric": {f"l{i}": '"q"' * 100 for i in range(80)}}]}
    result = await registry(metrics=FakeMetrics(wide)).call("query_metrics", {"query": "up"})
    assert len(result.text) <= 20_000
    assert json.loads(result.text)["truncated_for_size"] is True


async def test_scalar_results_are_not_reported_as_series():
    reg = registry(metrics=FakeMetrics({"resultType": "scalar", "result": [1_794_000_000, "2"]}))
    body = json.loads((await reg.call("query_metrics", {"query": "scalar(sum(up))"})).text)
    assert body == {"result_type": "scalar", "value": [1_794_000_000, "2"]}


async def test_null_time_arguments_mean_defaults():
    ok = await registry().call("query_logs", {"query": "x", "start": None, "end": None})
    assert not ok.is_error


async def test_window_caps_per_source():
    reg = registry()
    assert (await reg.call("query_traces", {"service": "core", "start": "now-15d"})).is_error
    assert (await reg.call("query_metrics_range", {"query": "up", "start": "now-8d", "step": "1h"})).is_error


async def test_list_trace_services_and_secret_named_fields_are_masked():
    reg = registry(logs=FakeLogs([{"_msg": "ok", "authorization": "short"}]))
    assert not (await reg.call("list_trace_services", {})).is_error
    assert "short" not in (await reg.call("query_logs", {"query": "x"})).text


async def test_url_query_strings_and_empty_events_are_dropped_from_spans():
    events = [{"timestamp": 1, "fields": [{"key": "noise", "value": "x"}]}]
    t = trace([span("a", None, 1_000, 5, {"http.url": "/reset?code=123456"}, logs=events)])
    text = (await registry(traces=FakeTraces([t])).call("get_trace", {"trace_id": TRACE_ID})).text
    assert "/reset" in text and "123456" not in text and "events" not in text


async def test_log_templates_compares_the_alarm_window_with_the_one_before():
    before = [{"_msg": f"cache refresh {i} took {10 + i}ms"} for i in range(10)]
    during = [{"_msg": f"cache refresh {i} took {10 + i}ms"} for i in range(5)]
    during += [{"_msg": f"refund to AT611904300234573201 failed on try {i}"} for i in range(4)]
    logs = FakeLogs(batches=[before, during])
    body = json.loads((await registry(logs=logs).call("log_templates", {"query": "*"})).text)
    # baseline is asked first and ends where the alarm window starts
    assert logs.calls[0][2] == logs.calls[1][1]
    assert (logs.calls[1][2] - logs.calls[1][1]) == (logs.calls[0][2] - logs.calls[0][1])
    assert body["lines"] == {"window": 9, "baseline": 10}
    assert body["new_templates"][0]["window"] == 4
    # drain3 leaves an IBAN as it is; the registry's masker is what hides it
    assert "AT61" not in json.dumps(body) and "<IBAN_1>" in json.dumps(body)
    assert body["window_truncated"] is False and body["baseline_truncated"] is False and "caution" not in body


async def test_log_templates_window_is_bounded_and_flags_possible_truncation():
    reg = registry(logs=FakeLogs([{"_msg": "x"}] * 2001))
    too_long = await reg.call("log_templates", {"query": "*", "start": "now-7h"})
    assert too_long.is_error and "longer" in too_long.text
    body = json.loads((await reg.call("log_templates", {"query": "*"})).text)
    assert body["window_truncated"] is True and body["baseline_truncated"] is True
    assert "new and vanished templates can be wrong" in body["caution"]


async def test_log_templates_rejects_a_baseline_older_than_the_log_window():
    reg = registry(logs=FakeLogs())
    result = await reg.call("log_templates", {"query": "*", "start": "now-20h", "end": "now-15h"})
    assert result.is_error and "24 hours" in result.text
    assert not (await reg.call("log_templates", {"query": "*", "start": "now-11h", "end": "now-6h"})).is_error


async def test_log_templates_rejects_an_end_in_the_future():
    args = {"query": "*", "start": "now-5m", "end": "2026-11-12T12:30:00Z"}  # NOW is 12:00 in these tests
    result = await registry(logs=FakeLogs()).call("log_templates", args)
    assert result.is_error and "future" in result.text


def source_row(service, lines=1, sample="x", host="t"):
    return {"service": service, "host": host, "lines": str(lines), "sample": sample}


async def test_list_log_sources_returns_one_entry_per_service_busiest_first_with_a_short_masked_sample():
    rows = [
        source_row("coolify", 2191, "login by ben@example.at"),
        source_row("core", 74, "Picked up JAVA_TOOL_OPTIONS" + "x" * 5000),
    ]
    logs = FakeLogs(rows)
    result = await registry(logs=logs).call("list_log_sources", {})
    body = json.loads(result.text)
    assert [(s["service"], s["lines"]) for s in body["sources"]] == [("coolify", 2191), ("core", 74)]
    assert len(body["sources"][1]["sample"]) <= 200 and body["truncated"] is False
    assert "example.at" not in result.text  # the sample is log text: it is masked like everything else
    query = logs.calls[0][0]  # grouped by the database, not line by line in Python
    assert query.startswith("service:*") and "stats by (service, host)" in query and "sort by (lines desc)" in query
    assert (logs.calls[0][2] - logs.calls[0][1]).total_seconds() == 24 * 3600


async def test_the_source_filter_is_an_exact_stream_filter_so_one_name_does_not_pick_up_another():
    rows = [source_row("core"), source_row("core-db"), source_row('od"d')]
    body = json.loads((await registry(logs=FakeLogs(rows)).call("list_log_sources", {})).text)
    filters = {s["service"]: s["filter"] for s in body["sources"]}
    assert filters["core"] == '{service="core"}' and filters["core-db"] == '{service="core-db"}'
    assert filters['od"d'] == '{service="od\\"d"}'  # a quote in a name cannot end the filter early


async def test_list_log_sources_says_when_there_are_more_sources_than_fit():
    rows = [source_row(f"svc{i}", i + 1) for i in range(200)]
    body = json.loads((await registry(logs=FakeLogs(rows)).call("list_log_sources", {})).text)
    assert body["truncated"] is True  # the flag survives the registry's own size trimming of the list


def test_the_prompt_sends_the_agent_to_list_log_sources_first():
    from app.agent.analyst import system_prompt

    assert "list_log_sources" in system_prompt("Acme", "") and "list_log_sources" in {
        d["name"] for d in registry().definitions()
    }
