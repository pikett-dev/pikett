"""Ports for the telemetry backends, so the tools run against fakes in tests (same idea as app/notify/base.py)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


class LogSource(Protocol):
    async def query(self, query: str, start: datetime, end: datetime, limit: int) -> list[dict[str, Any]]:
        """Runs a LogsQL query and returns up to `limit` of the most recent rows."""
        ...


class MetricSource(Protocol):
    async def instant(self, query: str, at: datetime) -> dict[str, Any]:
        """Instant MetricsQL query; returns the response `data` object (`resultType`, `result`)."""
        ...

    async def range(self, query: str, start: datetime, end: datetime, step_seconds: int) -> dict[str, Any]:
        """Range MetricsQL query; returns the response `data` object."""
        ...


class TraceSource(Protocol):
    async def services(self) -> list[str]: ...

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
        """Returns Jaeger-style trace objects (`traceID`, `spans`, `processes`)."""
        ...

    async def get_trace(self, trace_id: str) -> dict[str, Any]: ...


DEPLOYMENTS_PER_APP = 20  # how many deploys per application a ChangeSource returns at most


@dataclass(frozen=True)
class Deployment:
    service: str  # the Coolify application name, the same as `service` on logs and metrics
    repo: str | None  # workspace/slug on Bitbucket, None when the app is not built from Bitbucket
    commit: str
    message: str
    status: str  # Coolify: finished, failed, in_progress, queued, cancelled-by-user
    created_at: datetime
    finished_at: datetime | None
    pull_request_id: int  # 0 for the app itself, else a preview deploy
    rollback: bool


class ChangeSource(Protocol):
    async def deployments(self) -> tuple[list[Deployment], list[str]]:
        """The latest deployments of every application, and the applications whose deployments could not be read."""
        ...

    async def repos(self) -> dict[str, str | None]:
        """Application name -> its Bitbucket repository (workspace/slug), None when it is not built from Bitbucket."""
        ...

    async def commits(self, repo: str, new: str, old: str, limit: int) -> list[dict[str, Any]]:
        """Bitbucket commits reachable from `new` but not from `old`, newest first."""
        ...

    async def diffstat(self, repo: str, new: str, old: str, limit: int) -> tuple[list[dict[str, Any]], int]:
        """Changed files from `old` to `new` (not from their merge base) and the total number of files."""
        ...

    async def diff(self, repo: str, new: str, old: str, path: str | None) -> tuple[str, bool]:
        """The unified diff from `old` to `new`, optionally for one path, and whether it was cut short."""
        ...


@dataclass(frozen=True)
class Sources:
    logs: LogSource
    metrics: MetricSource
    traces: TraceSource
    changes: ChangeSource | None = None  # None when Coolify is not configured
