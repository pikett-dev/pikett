import json
from datetime import UTC, datetime
from urllib.parse import parse_qs

import httpx
import pytest

from app.agent.errors import SourceError
from app.agent.victoria import VictoriaLogs, VictoriaMetrics, VictoriaTraces

START = datetime(2026, 11, 12, 11, 0, tzinfo=UTC)
END = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)


def client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_logs_posts_a_form_and_parses_json_lines():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text='{"_msg":"a"}\n{"_msg":"b"}\n')

    async with client(handler) as http:
        rows = await VictoriaLogs("http://vl:9428/", http).query("error", START, END, 5)

    assert rows == [{"_msg": "a"}, {"_msg": "b"}]
    request = seen[0]
    assert request.method == "POST"
    assert request.url.path == "/select/logsql/query"
    form = parse_qs(request.content.decode())
    assert form["query"] == ["error"]
    assert form["start"] == ["2026-11-12T11:00:00Z"]
    assert form["end"] == ["2026-11-12T12:00:00Z"]
    assert form["limit"] == ["5"]


async def test_logs_error_carries_the_server_message():
    def handler(request):
        return httpx.Response(400, text="cannot parse `query` arg [error AND (]")

    async with client(handler) as http:
        with pytest.raises(SourceError, match="400.*cannot parse"):
            await VictoriaLogs("http://vl:9428", http).query("error AND (", START, END, 5)


async def test_unreachable_backend_becomes_a_source_error():
    def handler(request):
        raise httpx.ConnectError("refused")

    async with client(handler) as http:
        with pytest.raises(SourceError, match="not reachable"):
            await VictoriaMetrics("http://vm:8428", http).instant("up", END)


async def test_metrics_instant_and_range_send_epoch_seconds_and_return_data():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector", "result": []}})

    async with client(handler) as http:
        vm = VictoriaMetrics("http://vm:8428", http)
        assert await vm.instant("up", END) == {"resultType": "vector", "result": []}
        await vm.range("up", START, END, 60)

    first = parse_qs(seen[0].content.decode())
    assert seen[0].url.path == "/api/v1/query"
    assert first["time"] == [str(int(END.timestamp()))]
    second = parse_qs(seen[1].content.decode())
    assert seen[1].url.path == "/api/v1/query_range"
    assert second["step"] == ["60s"]
    assert second["start"] == [str(int(START.timestamp()))]


async def test_metrics_error_status_is_reported():
    def handler(request):
        return httpx.Response(400, json={"status": "error", "errorType": "400", "error": "unexpected token"})

    async with client(handler) as http:
        with pytest.raises(SourceError, match="unexpected token"):
            await VictoriaMetrics("http://vm:8428", http).instant("sum(", END)


async def test_traces_search_uses_microseconds_and_json_tags():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": [{"traceID": "abc", "spans": []}], "errors": None})

    async with client(handler) as http:
        traces = await VictoriaTraces("http://vt:10428", http).search(
            "core", START, END, 3, operation="GET /x", tags={"error": "true"}, min_duration="500ms"
        )

    assert traces == [{"traceID": "abc", "spans": []}]
    params = seen[0].url.params
    assert seen[0].url.path == "/select/jaeger/api/traces"
    assert params["service"] == "core"
    assert params["start"] == str(int(START.timestamp() * 1_000_000))
    assert json.loads(params["tags"]) == {"error": "true"}
    assert params["minDuration"] == "500ms"
    assert params["limit"] == "3"


async def test_trace_not_found_uses_the_server_message():
    def handler(request):
        return httpx.Response(404, json={"data": [], "errors": [{"code": 404, "msg": "trace not found"}]})

    async with client(handler) as http:
        with pytest.raises(SourceError, match="trace not found"):
            await VictoriaTraces("http://vt:10428", http).get_trace("abcdabcdabcdabcd")


async def test_trace_services():
    def handler(request):
        return httpx.Response(200, json={"data": ["core", "admin-frontend"], "errors": None})

    async with client(handler) as http:
        assert await VictoriaTraces("http://vt:10428", http).services() == ["core", "admin-frontend"]


async def test_empty_jaeger_answers_are_empty_lists_not_errors():
    def handler(request):
        return httpx.Response(200, json={"data": None, "errors": None})

    async with client(handler) as http:
        vt = VictoriaTraces("http://vt:10428", http)
        assert await vt.services() == []
        assert await vt.search("core", START, END, 5) == []
