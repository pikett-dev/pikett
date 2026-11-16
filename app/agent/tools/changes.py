"""The read-only change tools: Coolify deploys and the Bitbucket commits and diffs between them. The backend sits
behind `ChangeSource` in `app/agent/ports.py`; the tools exist only when Coolify is configured."""

import asyncio
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from app.agent.errors import SourceError, ToolInputError
from app.agent.ports import DEPLOYMENTS_PER_APP, ChangeSource, Deployment
from app.agent.timewindow import resolve_window
from app.agent.tools.definitions import _TIME_PROPERTIES, _optional, _required
from app.agent.tools.registry import Tool

_CHANGE_WINDOW = timedelta(hours=24)
_MAX_DEPLOYS = 10  # per service and window
_MAX_COMMITS = 20  # per deploy
_MAX_FILES = 40  # per deploy
_MAX_DIFF_LINES = 400
_MAX_LINE_CHARS = 300  # a minified bundle or lockfile line would eat the budget
_BITBUCKET_PARALLEL = 4
_SHA = re.compile(r"[0-9a-f]{7,40}")
_FULL_SHA = re.compile(
    r"[0-9a-f]{40}"
)  # Bitbucket redirects a short hash on the diff endpoint, so the tool wants all 40
_SHA_PROPERTY = {"type": "string", "pattern": f"^{_FULL_SHA.pattern}$"}


def _first_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[0] if lines else ""


def _author(commit: dict[str, Any]) -> str:
    """The name only: `Name <mail>` loses the address here. Names are not masked; addresses would be."""
    author = commit.get("author") or {}
    user = author.get("user") or {}
    return str(user.get("display_name") or str(author.get("raw", "")).split("<")[0]).strip()


def _commit_rows(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "commit": c.get("hash", ""),
            "date": c.get("date", ""),
            "author": _author(c),
            "summary": _first_line(str(c.get("message", ""))),
        }
        for c in commits
    ]


def _went_live(d: Deployment) -> bool:
    """Finished with a real commit: Coolify keeps `HEAD` on deploys that never resolved one."""
    return d.status == "finished" and d.finished_at is not None and _SHA.fullmatch(d.commit) is not None


def _deploy_summary(d: Deployment) -> dict[str, Any]:
    return {
        "commit": d.commit,
        "message": _first_line(d.message),
        "status": d.status,
        "went_live": _went_live(d),
        "started": d.created_at.isoformat(),
        "finished": d.finished_at.isoformat() if d.finished_at else None,
        **({"preview_pull_request": d.pull_request_id} if d.pull_request_id else {}),
        **({"rollback": True} if d.rollback else {}),
    }


async def _commits_part(
    changes: ChangeSource, repo: str, deploy: Deployment, base: str, limit: asyncio.Semaphore
) -> dict[str, Any]:
    async with limit:
        try:
            commits = await changes.commits(repo, deploy.commit, base, _MAX_COMMITS)
            part: dict[str, Any] = {
                "commits": _commit_rows(commits),
                "commits_may_be_more": len(commits) >= _MAX_COMMITS,
            }
            if not commits:  # a rollback: the base has commits the deploy does not
                part["reverted_commits"] = _commit_rows(await changes.commits(repo, base, deploy.commit, _MAX_COMMITS))
            return part
        except (SourceError, AttributeError, TypeError) as exc:  # the latter two: a row of an unexpected shape
            return {"commits_error": str(exc) if isinstance(exc, SourceError) else "unexpected commit data"}


async def _files_part(
    changes: ChangeSource, repo: str, deploy: Deployment, base: str, limit: asyncio.Semaphore
) -> dict[str, Any]:
    async with limit:
        try:
            files, total = await changes.diffstat(repo, deploy.commit, base, _MAX_FILES)
            rows = [
                {
                    "path": (f.get("new") or f.get("old") or {}).get("path", ""),
                    "status": f.get("status", ""),
                    "added": f.get("lines_added", 0),
                    "removed": f.get("lines_removed", 0),
                }
                for f in files
            ]
        except (SourceError, AttributeError, TypeError) as exc:  # the latter two: a row of an unexpected shape
            return {"files_error": str(exc) if isinstance(exc, SourceError) else "unexpected file data"}
    return {"files": rows, "files_total": total}


async def _deploy_entry(
    changes: ChangeSource, deploy: Deployment, before: Deployment | None, limit: asyncio.Semaphore
) -> dict[str, Any]:
    """One deploy with what it changed compared to the deploy that was live before it."""
    entry = _deploy_summary(deploy)
    entry["base_commit"] = (
        before.commit if before else None
    )  # None: no earlier live deploy among the latest ones Coolify keeps
    if before is None or not entry["went_live"] or deploy.repo is None:
        return entry  # a deploy that never went live changed nothing that ran
    if before.commit == deploy.commit:
        entry["same_commit_as_before"] = True  # a redeploy or restart: no code changed
        return entry
    for part in await asyncio.gather(
        _commits_part(changes, deploy.repo, deploy, before.commit, limit),
        _files_part(changes, deploy.repo, deploy, before.commit, limit),
    ):
        entry.update(part)
    return entry


def _live_before(live: list[Deployment], deploy: Deployment) -> Deployment | None:
    """The deploy that was live before this one started; a preview is compared with the preview before it."""
    return next(
        (
            d
            for d in live  # newest first
            if d.finished_at is not None
            and d.finished_at <= deploy.created_at
            and d.pull_request_id == deploy.pull_request_id
        ),
        None,
    )


async def _service_report(
    changes: ChangeSource,
    name: str,
    history: list[Deployment],
    start: datetime,
    end: datetime,
    limit: asyncio.Semaphore,
) -> dict[str, Any]:
    live = [d for d in history if _went_live(d)]
    # A deploy that started before the window but went live inside it counts.
    in_window = [d for d in history if d.created_at <= end and start <= (d.finished_at or d.created_at)]
    entries = await asyncio.gather(
        *(_deploy_entry(changes, d, _live_before(live, d), limit) for d in in_window[:_MAX_DEPLOYS])
    )
    live_at_end = next(
        (d for d in live if d.finished_at is not None and d.finished_at <= end and not d.pull_request_id), None
    )
    return {
        "service": name,
        "live_at_end": _deploy_summary(live_at_end) if live_at_end else None,
        "deploys": entries,
        "deploys_may_be_more": len(in_window) > _MAX_DEPLOYS,
        # The source keeps only the latest deploys; if all of them are newer than the window, older ones are missing.
        **(
            {"history_cut_before_window": True}
            if len(history) >= DEPLOYMENTS_PER_APP and history[-1].created_at > start
            else {}
        ),
    }


def change_tools(changes: ChangeSource, clock: Callable[[], datetime]) -> list[Tool]:
    async def recent_changes(args: dict[str, Any]) -> Any:
        start, end = resolve_window(args, clock(), max_span=_CHANGE_WINDOW, default_start="now-6h")
        service = _optional(args, "service")
        deploys, unavailable = await changes.deployments()
        grouped: dict[str, list[Deployment]] = {}
        for d in sorted(deploys, key=lambda d: d.created_at, reverse=True):
            grouped.setdefault(d.service, []).append(d)
        if service and service not in grouped and service not in unavailable:
            raise ToolInputError(f"unknown service {service!r}; known: {', '.join(sorted(grouped))}")
        limit = asyncio.Semaphore(_BITBUCKET_PARALLEL)  # shared: bounds Bitbucket calls across all services
        result = await asyncio.gather(
            *(
                _service_report(changes, name, grouped.get(name, []), start, end, limit)
                for name in ([service] if service else sorted(grouped))
            )
        )
        return {
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "services": list(result),
            **({"services_unavailable": unavailable} if unavailable else {}),
        }

    async def get_change_diff(args: dict[str, Any]) -> Any:
        service = _required(args, "service")
        commit = _required(args, "commit", _FULL_SHA, "the full 40-character hash from recent_changes")
        base = _required(args, "base_commit", _FULL_SHA, "the full 40-character base_commit from recent_changes")
        path = _optional(args, "path")
        repos = await changes.repos()
        if service not in repos:
            raise ToolInputError(f"unknown service {service!r}; known: {', '.join(sorted(repos))}")
        repo = repos[service]
        if repo is None:
            raise ToolInputError(f"{service} is not built from a Bitbucket repository")
        text, cut = await changes.diff(repo, commit, base, path)
        lines = text.splitlines()
        return {
            "lines": [line[:_MAX_LINE_CHARS] for line in lines[:_MAX_DIFF_LINES]],
            "lines_total": len(lines),
            "truncated": cut or len(lines) > _MAX_DIFF_LINES,
        }

    return [
        Tool(
            "recent_changes",
            "What changed before the alarm: the Coolify deploys of each service in the window (default the last 6 "
            "hours, at most 24), newest first. A deploy that `went_live` lists the commits and changed files "
            "compared to the deploy that was live before it (`base_commit`, null when that deploy is not among the "
            "latest ones Coolify keeps); a rollback lists `reverted_commits`; "
            "`same_commit_as_before` means no code changed; failed or unfinished deploys never ran. `live_at_end` "
            "is the commit that ran at the end of the window. A deploy shortly before the alarm is the first "
            "suspect, but it is only a cause if logs or traces show it.",
            {
                "type": "object",
                "properties": {
                    "start": {"type": "string", "description": "Window start, default 'now-6h', at most 24 hours."},
                    "end": _TIME_PROPERTIES["end"],
                    "service": {"type": "string", "description": "Only this service, for example `core`."},
                },
            },
            recent_changes,
        ),
        Tool(
            "get_change_diff",
            f"The code diff of a deploy: from `base_commit` to `commit` as recent_changes gives them, optionally for "
            f"one file path. Returns up to {_MAX_DIFF_LINES} lines of the unified diff, fewer if they are long.",
            {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "The service, for example `core`."},
                    "commit": {**_SHA_PROPERTY, "description": "The deployed commit."},
                    "base_commit": {**_SHA_PROPERTY, "description": "The commit that was live before."},
                    "path": {"type": "string", "description": "Only this file, a path from `files`."},
                },
                "required": ["service", "commit", "base_commit"],
            },
            get_change_diff,
        ),
    ]
