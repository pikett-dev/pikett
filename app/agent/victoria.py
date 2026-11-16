"""Read-only clients for VictoriaLogs, VictoriaMetrics and VictoriaTraces (Jaeger-compatible API).

Endpoints and parameters follow the live docs and were checked against the running servers (2026-11-12):
`/select/logsql/query`, `/api/v1/query[_range]` and `/select/jaeger/api/...`. Only reads happen here.
"""

import json
from datetime import UTC, datetime
from typing import Any

import httpx

from app.agent.errors import SourceError
from app.agent.ports import Sources

_QUERY_TIMEOUT_SECONDS = 10
_HTTP_TIMEOUT_SECONDS = _QUERY_TIMEOUT_SECONDS + 5


def _error_text(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            return str(errors[0].get("msg", ""))[:300]
        if "error" in body:
            return str(body["error"])[:300]
    return response.text[:300]


async def _request(client: httpx.AsyncClient, what: str, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        response = await client.request(method, url, timeout=_HTTP_TIMEOUT_SECONDS, **kwargs)
    except httpx.HTTPError as exc:
        raise SourceError(f"{what} is not reachable ({type(exc).__name__})") from exc
    if response.status_code >= 400:
        raise SourceError(f"{what} returned {response.status_code}: {_error_text(response)}")
    return response


def _json(response: httpx.Response, what: str) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        raise SourceError(f"{what} returned a body that is not JSON") from exc


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_seconds(moment: datetime) -> str:
    return str(int(moment.timestamp()))


def _epoch_micros(moment: datetime) -> int:
    return int(moment.timestamp() * 1_000_000)


class VictoriaLogs:
    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self._url = base_url.rstrip("/") + "/select/logsql/query"
        self._client = client

    async def query(self, query: str, start: datetime, end: datetime, limit: int) -> list[dict[str, Any]]:
        form = {
            "query": query,
            "start": _rfc3339(start),
            "end": _rfc3339(end),
            "limit": str(limit),
            "timeout": f"{_QUERY_TIMEOUT_SECONDS}s",
        }
        response = await _request(self._client, "VictoriaLogs", "POST", self._url, data=form)
        try:
            return [json.loads(line) for line in response.text.splitlines() if line.strip()]
        except ValueError as exc:
            raise SourceError("VictoriaLogs returned a line that is not JSON") from exc


class VictoriaMetrics:
    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self._base = base_url.rstrip("/") + "/api/v1/"
        self._client = client

    async def _run(self, path: str, form: dict[str, str]) -> dict[str, Any]:
        form = {**form, "timeout": f"{_QUERY_TIMEOUT_SECONDS}s"}
        response = await _request(self._client, "VictoriaMetrics", "POST", self._base + path, data=form)
        payload = _json(response, "VictoriaMetrics")
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise SourceError(f"VictoriaMetrics query failed: {str(payload)[:300]}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise SourceError("VictoriaMetrics returned no data object")
        return data

    async def instant(self, query: str, at: datetime) -> dict[str, Any]:
        return await self._run("query", {"query": query, "time": _epoch_seconds(at)})

    async def range(self, query: str, start: datetime, end: datetime, step_seconds: int) -> dict[str, Any]:
        form = {"query": query, "start": _epoch_seconds(start), "end": _epoch_seconds(end), "step": f"{step_seconds}s"}
        return await self._run("query_range", form)


class VictoriaTraces:
    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self._base = base_url.rstrip("/") + "/select/jaeger/api/"
        self._client = client

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        response = await _request(self._client, "VictoriaTraces", "GET", self._base + path, params=params)
        payload = _json(response, "VictoriaTraces")
        data = payload.get("data") if isinstance(payload, dict) else None
        if data is None and isinstance(payload, dict) and "data" in payload:
            return []  # Jaeger answers {"data": null} when nothing matches
        if not isinstance(data, list):
            raise SourceError("VictoriaTraces returned no data list")
        return data

    async def services(self) -> list[str]:
        return [str(name) for name in await self._get("services")]

    async def search(
        self,
        service: str,
        start: datetime,
        end: datetime,
        limit: int,
        *,
        operation: str | None = None,
        tags: dict[str, str] | None = None,
        min_duration: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "service": service,
            "start": _epoch_micros(start),
            "end": _epoch_micros(end),
            "limit": limit,
        }
        if operation:
            params["operation"] = operation
        if tags:
            params["tags"] = json.dumps(tags)
        if min_duration:
            params["minDuration"] = min_duration
        return [trace for trace in await self._get("traces", params) if isinstance(trace, dict)]

    async def get_trace(self, trace_id: str) -> dict[str, Any]:
        traces = await self._get(f"traces/{trace_id}")
        if not traces or not isinstance(traces[0], dict):
            raise SourceError("trace not found")
        return traces[0]


def build_sources(logs_url: str, metrics_url: str, traces_url: str, client: httpx.AsyncClient) -> Sources:
    return Sources(
        logs=VictoriaLogs(logs_url, client),
        metrics=VictoriaMetrics(metrics_url, client),
        traces=VictoriaTraces(traces_url, client),
    )
