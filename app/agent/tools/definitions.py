"""The read-only telemetry tools: logs, metrics, traces. Backends sit behind the ports in `app/agent/ports.py`."""

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from app.agent.errors import ToolInputError
from app.agent.fingerprints import MAX_ROWS, baseline_window, fingerprint_window
from app.agent.ports import Sources
from app.agent.timewindow import parse_duration_seconds, parse_time, resolve_window
from app.agent.tools.registry import Tool

_LOG_WINDOW = timedelta(hours=24)
_METRIC_WINDOW = timedelta(days=7)
_TRACE_WINDOW = timedelta(days=14)  # VictoriaTraces keeps 14 days
_MAX_LOG_ROWS = 200
_TEMPLATE_WINDOW = timedelta(hours=6)  # the baseline is as long again; log_templates checks it stays within 24 h
_MAX_SERIES = 50
_MAX_POINTS = 500
_MAX_TRACES = 20
_MAX_TRACE_SPANS = 60  # a trace with more spans keeps all error spans plus the slowest others
# `service` is set by Alloy: the Coolify resource name (the same as `service.name` in the traces), else the container
# name without the deploy time. It is a stream field, so the filter below is a cheap stream filter.
_SOURCES_QUERY = "service:* | stats by (service, host) count() as lines, any(_msg) as sample | sort by (lines desc)"
_SAMPLE_CHARS = 200  # one line only has to identify the service
_TRACE_ID = re.compile(r"[0-9a-fA-F]{16,32}")
_MIN_DURATION = re.compile(r"\d+(?:ns|us|ms|s|m|h)")
# An allowlist, not a mask: Jaeger spans carry many tags (SQL statements, request headers) and only these reach the
# agent. Whatever is shown is still masked by the registry. Add a tag here when an analysis needs it.
# `jdbc.query[0]` is accepted on the assumption of prepared statements (`?` placeholders): a statement with literal
# values would carry names and addresses that no masker rule recognises.
_SHOWN_SPAN_TAGS = frozenset(
    {
        "error",
        "exception",
        "otel.status_description",
        "http.url",
        "http.method",
        "http.response.status_code",
        "method",
        "status",
        "uri",
        "outcome",
        "peer.service",
        "jdbc.query[0]",
        "next.route",
    }
)

_SHOWN_EVENT_FIELDS = frozenset({"event", "message", "exception.type", "exception.message", "exception.stacktrace"})
_METRIC_RETENTION = timedelta(days=90)

_TIME_PROPERTIES = {
    "start": {"type": "string", "description": "Window start: 'now-30m' or an RFC 3339 timestamp. Default 'now-1h'."},
    "end": {"type": "string", "description": "Window end: 'now' (default) or an RFC 3339 timestamp."},
}


def _optional(args: dict[str, Any], key: str, pattern: re.Pattern[str] | None = None, hint: str = "") -> str | None:
    value = args.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ToolInputError(f"'{key}' must be a string")
    if pattern is not None and not pattern.fullmatch(value):
        raise ToolInputError(f"'{key}' must be {hint}")
    return value


def _required(args: dict[str, Any], key: str, pattern: re.Pattern[str] | None = None, hint: str = "") -> str:
    value = _optional(args, key, pattern, hint)
    if value is None:
        raise ToolInputError(f"'{key}' is required")
    return value


def _bool(args: dict[str, Any], key: str) -> bool:
    value = args.get(key, False)
    if not isinstance(value, bool):
        raise ToolInputError(f"'{key}' must be true or false")
    return value


def _int(args: dict[str, Any], key: str, default: int, maximum: int) -> int:
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ToolInputError(f"'{key}' must be an integer from 1 to {maximum}")
    return value


def _tag_value(key: str, value: Any) -> Any:
    # Query strings can carry reset codes and ids no masker rule knows; the path is enough for an analysis.
    return value.split("?", 1)[0] if key == "http.url" and isinstance(value, str) else value


def _tags(span: dict[str, Any]) -> dict[str, Any]:
    return {
        t["key"]: _tag_value(t["key"], t.get("value")) for t in span.get("tags", []) if t.get("key") in _SHOWN_SPAN_TAGS
    }


def _is_error(span: dict[str, Any]) -> bool:
    return any(
        (t.get("key") == "error" and str(t.get("value")).lower() == "true")
        or (t.get("key") == "otel.status_code" and str(t.get("value")).upper() == "ERROR")
        for t in span.get("tags", [])
    )


def _parent_id(span: dict[str, Any]) -> str | None:
    for ref in span.get("references", []):
        if ref.get("refType") == "CHILD_OF":
            ref_id = ref.get("spanID")
            return None if ref_id is None else str(ref_id)
    return None


def _service(trace: dict[str, Any], span: dict[str, Any]) -> str:
    process = trace.get("processes", {}).get(span.get("processID"), {})
    return str(process.get("serviceName", "?"))


def _iso_micros(micros: int) -> str:
    return datetime.fromtimestamp(micros / 1_000_000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _summarise_trace(trace: dict[str, Any]) -> dict[str, Any]:
    spans = trace.get("spans", [])
    summary: dict[str, Any] = {
        "trace_id": trace.get("traceID"),
        "root": None,
        "start": None,
        "duration_ms": None,
        "spans": len(spans),
        "error_spans": sum(1 for s in spans if _is_error(s)),
    }
    if spans:
        ids = {s.get("spanID") for s in spans}
        root = min(
            (s for s in spans if _parent_id(s) not in ids), key=lambda s: s.get("startTime", 0), default=spans[0]
        )
        summary["root"] = f"{_service(trace, root)}: {root.get('operationName')}"
        summary["start"] = _iso_micros(root.get("startTime", 0))
        summary["duration_ms"] = round(root.get("duration", 0) / 1000, 1)
    return summary


def _span_view(trace: dict[str, Any], span: dict[str, Any], origin: int) -> dict[str, Any]:
    view: dict[str, Any] = {
        "span_id": span.get("spanID"),
        "parent_id": _parent_id(span),
        "service": _service(trace, span),
        "operation": span.get("operationName"),
        "offset_ms": round((span.get("startTime", 0) - origin) / 1000, 1),
        "duration_ms": round(span.get("duration", 0) / 1000, 1),
        "error": _is_error(span),
    }
    if tags := _tags(span):
        view["tags"] = tags
    events = [
        {f["key"]: f.get("value") for f in log.get("fields", []) if f.get("key") in _SHOWN_EVENT_FIELDS}
        for log in span.get("logs", [])
    ]
    events = [e for e in events if e][:5]
    if events:
        view["events"] = events
    return view


def _flatten_trace(trace: dict[str, Any]) -> dict[str, Any]:
    """A compact span list: error spans first when the trace is too big, then in time order."""
    spans = sorted(trace.get("spans", []), key=lambda s: s.get("startTime", 0))
    shown = spans
    if len(spans) > _MAX_TRACE_SPANS:
        errors = [s for s in spans if _is_error(s)]
        others = sorted((s for s in spans if not _is_error(s)), key=lambda s: -s.get("duration", 0))
        shown = sorted((errors + others)[:_MAX_TRACE_SPANS], key=lambda s: s.get("startTime", 0))
    origin = spans[0].get("startTime", 0) if spans else 0
    return {
        "trace_id": trace.get("traceID"),
        "spans_total": len(spans),
        "spans_shown": len(shown),
        "spans": [_span_view(trace, s, origin) for s in shown],
    }


def _series(data: dict[str, Any]) -> dict[str, Any]:
    result = data.get("result", [])
    if data.get("resultType") in ("scalar", "string"):  # a single [timestamp, value] pair, not a list of series
        return {"result_type": data.get("resultType"), "value": result}
    return {
        "result_type": data.get("resultType"),
        "series_total": len(result),
        "series": result[:_MAX_SERIES],
        "truncated": len(result) > _MAX_SERIES,
    }


def victoria_tools(sources: Sources, clock: Callable[[], datetime]) -> list[Tool]:
    async def query_logs(args: dict[str, Any]) -> Any:
        query = _required(args, "query")
        limit = _int(args, "limit", 50, _MAX_LOG_ROWS)
        start, end = resolve_window(args, clock(), max_span=_LOG_WINDOW)
        rows = await sources.logs.query(query, start, end, limit)
        return {
            "rows": rows,
            "returned": len(rows),
            "limit": limit,
            "may_have_more": len(rows) >= limit,
            "window": {"start": start.isoformat(), "end": end.isoformat()},
        }

    async def list_log_sources(args: dict[str, Any]) -> Any:
        start, end = resolve_window(args, clock(), max_span=_LOG_WINDOW, default_start="now-24h")
        rows = await sources.logs.query(_SOURCES_QUERY, start, end, _MAX_LOG_ROWS)
        return {
            "sources": [
                {
                    "service": row["service"],
                    "host": row.get("host", ""),
                    "lines": int(row.get("lines", 0)),
                    # An exact match: `core` must not also pick up `core-db`.
                    "filter": f"{{service={json.dumps(row['service'], ensure_ascii=False)}}}",
                    "sample": str(row.get("sample", ""))[:_SAMPLE_CHARS],
                }
                for row in rows
            ],
            "truncated": len(rows) >= _MAX_LOG_ROWS,  # more sources than fit: the quietest are missing
            "window": {"start": start.isoformat(), "end": end.isoformat()},
        }

    async def log_templates(args: dict[str, Any]) -> Any:
        query = _required(args, "query")
        start, end = resolve_window(args, clock(), max_span=_TEMPLATE_WINDOW, default_start="now-30m")
        now = clock()
        if end > now + timedelta(minutes=1):  # an alert's endsAt lies ahead; compare real data only
            raise ToolInputError("'end' must not be in the future; use 'now'")
        baseline_start, baseline_end = baseline_window(start, end)
        if baseline_start < now - _LOG_WINDOW:  # an empty baseline would make every template look new
            raise ToolInputError("the window before the alarm window would reach back more than 24 hours; shorten it")
        report = await fingerprint_window(sources.logs, query, start, end)
        return {
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "baseline": {"start": baseline_start.isoformat(), "end": baseline_end.isoformat()},
            **report.as_dict(),
        }

    async def query_metrics(args: dict[str, Any]) -> Any:
        query = _required(args, "query")
        now = clock()
        at = parse_time(args.get("time") or "now", now)
        if not now - _METRIC_RETENTION <= at <= now + timedelta(minutes=1):
            raise ToolInputError(f"'time' must be within the last {_METRIC_RETENTION.days} days (the retention)")
        return _series(await sources.metrics.instant(query, at))

    async def query_metrics_range(args: dict[str, Any]) -> Any:
        query = _required(args, "query")
        start, end = resolve_window(args, clock(), max_span=_METRIC_WINDOW)
        step = parse_duration_seconds(args.get("step") or "1m")
        if (end - start).total_seconds() / step > _MAX_POINTS:
            raise ToolInputError(f"more than {_MAX_POINTS} points per series; use a larger step or a shorter window")
        return _series(await sources.metrics.range(query, start, end, step))

    async def list_trace_services(_: dict[str, Any]) -> Any:
        return {"services": await sources.traces.services()}

    async def query_traces(args: dict[str, Any]) -> Any:
        service = _required(args, "service")
        limit = _int(args, "limit", 10, _MAX_TRACES)
        min_duration = _optional(args, "min_duration", _MIN_DURATION, "like '500ms' or '2s'")
        errors_only = _bool(args, "errors_only")
        start, end = resolve_window(args, clock(), max_span=_TRACE_WINDOW)
        traces = await sources.traces.search(
            service,
            start,
            end,
            limit,
            operation=_optional(args, "operation"),
            tags={"error": "true"} if errors_only else None,
            min_duration=min_duration,
        )
        return {"traces": [_summarise_trace(t) for t in traces], "returned": len(traces), "limit": limit}

    async def get_trace(args: dict[str, Any]) -> Any:
        trace_id = _required(args, "trace_id", _TRACE_ID, "16 to 32 hex characters")
        return _flatten_trace(await sources.traces.get_trace(trace_id))

    tools = [
        Tool(
            "list_log_sources",
            "List where logs come from: one entry per service, busiest first, with the number of lines, one "
            "ready-made `filter` for the other log tools and one arbitrary sample line. The service names are the "
            "same as in list_trace_services (for example `core`, `admin-frontend`); host services from journald "
            "carry their systemd unit.",
            {
                "type": "object",
                "properties": {
                    "start": {
                        "type": "string",
                        "description": "Window start, default 'now-24h', at most 24 hours back.",
                    },
                    "end": _TIME_PROPERTIES["end"],
                },
            },
            list_log_sources,
        ),
        Tool(
            "query_logs",
            "Search logs with a LogsQL query. Returns the most recent matching rows (message, time, service, "
            "container, host). Container logs carry no severity, so search the message text, for example "
            '`_msg:~"(?i)error|exception"`, and narrow to one service with the `filter` that list_log_sources '
            "gives for it. A bare word searches the message.",
            {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": 'LogsQL, for example `<filter from list_log_sources> AND _msg:~"(?i)error"`.',
                    },
                    **_TIME_PROPERTIES,
                    "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_LOG_ROWS, "default": 50},
                },
                "required": ["query"],
            },
            query_logs,
        ),
        Tool(
            "log_templates",
            "Group the logs of the alarm window into templates and compare them with the window of the same length "
            "right before it. Shows templates that are new in the alarm window, templates that vanished, and the "
            "most frequent ones, each with counts for both windows. Start here to see what changed. If a window hit "
            f"the row cap ({MAX_ROWS} lines per window) the result says so and new/vanished can be wrong.",
            {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "LogsQL filter, for example `*` or a `filter` from list_log_sources.",
                    },
                    "start": {"type": "string", "description": "Alarm window start, default 'now-30m'."},
                    "end": {"type": "string", "description": "Alarm window end, default 'now'. At most 6 hours long."},
                },
                "required": ["query"],
            },
            log_templates,
        ),
        Tool(
            "query_metrics",
            f"Instant MetricsQL/PromQL query at one point in time. Returns up to {_MAX_SERIES} series.",
            {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "For example `up` or `rate(http_requests_total[5m])`."},
                    "time": {"type": "string", "description": "'now' (default), 'now-10m' or an RFC 3339 timestamp."},
                },
                "required": ["query"],
            },
            query_metrics,
        ),
        Tool(
            "query_metrics_range",
            f"MetricsQL/PromQL query over a time range, for trends. At most {_MAX_POINTS} points per series, "
            f"up to {_MAX_SERIES} series.",
            {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    **_TIME_PROPERTIES,
                    "step": {"type": "string", "description": "Resolution such as '30s', '5m'. Default '1m'."},
                },
                "required": ["query"],
            },
            query_metrics_range,
        ),
        Tool(
            "list_trace_services",
            "List the services that send traces. Use the names with query_traces.",
            {"type": "object", "properties": {}},
            list_trace_services,
        ),
        Tool(
            "query_traces",
            "Find traces of one service, newest first. Returns a summary per trace (root, duration, span count, "
            "error spans). Use get_trace for the span tree.",
            {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Service name from list_trace_services."},
                    "operation": {"type": "string", "description": "Optional span name, for example a route."},
                    "min_duration": {
                        "type": "string",
                        "pattern": f"^{_MIN_DURATION.pattern}$",
                        "description": "Only slow traces, for example '500ms' or '2s'.",
                    },
                    "errors_only": {"type": "boolean", "description": "Only traces with an error span."},
                    **_TIME_PROPERTIES,
                    "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_TRACES, "default": 10},
                },
                "required": ["service"],
            },
            query_traces,
        ),
        Tool(
            "get_trace",
            "Get the spans of one trace: parent, service, operation, timing, errors and the key tags.",
            {
                "type": "object",
                "properties": {
                    "trace_id": {
                        "type": "string",
                        "pattern": f"^{_TRACE_ID.pattern}$",
                        "description": "Trace id (hex).",
                    }
                },
                "required": ["trace_id"],
            },
            get_trace,
        ),
    ]
    return tools
