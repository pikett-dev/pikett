"""Read-only clients for what changed: Coolify deployments and the Bitbucket commits and diffs between them.

Checked against the live APIs on 2026-11-14 (the Coolify docs show an application object for the deployments
endpoint, the real answer is `{"count", "deployments": [...]}`, newest first):

- Coolify `GET /api/v1/applications` (uuid, name, git_repository) and
  `GET /api/v1/deployments/applications/{uuid}?take=N` (commit, commit_message, status, created_at, finished_at,
  pull_request_id, rollback), with the read-only token of the version and backup checks.
- Bitbucket Cloud `GET /2.0/repositories/{repo}/commits?include=<new>&exclude=<old>`, `.../diffstat/<new>..<old>` and
  `.../diff/<new>..<old>?path=...`, each with that repository's own access token (`repository` read scope). Diffs
  are asked for with `topic=false`: the default compares with the merge base, and a rollback then shows no change
  at all (checked: 0 files without, 44 with `topic=false`).
"""

import asyncio
import re
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import SecretStr

from app.agent.errors import SourceError
from app.agent.ports import DEPLOYMENTS_PER_APP, Deployment

_TIMEOUT_SECONDS = 15
_MAX_DIFF_BYTES = 1_000_000  # a lockfile or bundle change is cut here, long before it reaches the agent
_BITBUCKET_API = "https://api.bitbucket.org/2.0/repositories"
# git@bitbucket.org:acme/api.git or https://bitbucket.org/acme/api(.git)
_BITBUCKET_REPO = re.compile(r"bitbucket\.org[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$")


def _repo_of(git_repository: str) -> str | None:
    match = _BITBUCKET_REPO.search(git_repository or "")
    return match.group(1) if match else None


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (
        parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    )  # a zone-less stamp would not compare with aware ones


def _int(value: Any) -> int:
    try:
        return int(str(value or 0))
    except ValueError:
        return 0


def _flag(value: Any) -> bool:
    return value is True or str(value).lower() in {"1", "true"}


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _check(response: httpx.Response, what: str) -> None:
    if response.status_code >= 300:  # redirects are not followed: a short hash would answer 3xx with an empty body
        raise SourceError(f"{what} returned {response.status_code}")  # bodies may echo the request: not shown


async def _get_json(client: httpx.AsyncClient, what: str, url: str, token: str, **params: Any) -> Any:
    try:
        response = await client.get(url, params=params, headers=_headers(token), timeout=_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        raise SourceError(f"{what} is not reachable ({type(exc).__name__})") from exc
    _check(response, what)
    try:
        return response.json()
    except ValueError as exc:
        raise SourceError(f"{what} returned a body that is not JSON") from exc


def _values(body: Any, what: str) -> list[dict[str, Any]]:
    values = body.get("values", []) if isinstance(body, dict) else None
    if not isinstance(values, list):
        raise SourceError(f"{what} returned an unexpected body")
    return [v for v in values if isinstance(v, dict)]


class HttpChanges:
    def __init__(
        self,
        client: httpx.AsyncClient,
        coolify_url: str,
        coolify_token: SecretStr,
        bitbucket_tokens: dict[str, SecretStr],
    ) -> None:
        self._client = client
        self._coolify = coolify_url.rstrip("/")
        self._coolify_token = coolify_token
        self._bitbucket_tokens = {repo.lower(): token for repo, token in bitbucket_tokens.items()}  # slugs ignore case

    async def _applications(self) -> list[dict[str, Any]]:
        apps = await _get_json(
            self._client, "Coolify", f"{self._coolify}/api/v1/applications", self._coolify_token.get_secret_value()
        )
        if not isinstance(apps, list):
            raise SourceError("Coolify returned no list of applications")
        return [a for a in apps if isinstance(a, dict) and a.get("uuid") and a.get("name")]

    async def repos(self) -> dict[str, str | None]:
        return {str(a["name"]): _repo_of(str(a.get("git_repository", ""))) for a in await self._applications()}

    async def _app_deployments(self, app: dict[str, Any]) -> list[Deployment] | None:
        """None when Coolify cannot answer for this app: one broken app must not hide the others."""
        try:
            return await self._read_deployments(app)
        except SourceError:
            return None

    async def _read_deployments(self, app: dict[str, Any]) -> list[Deployment]:
        url = f"{self._coolify}/api/v1/deployments/applications/{app['uuid']}"
        body = await _get_json(
            self._client, "Coolify", url, self._coolify_token.get_secret_value(), take=DEPLOYMENTS_PER_APP
        )
        rows = body.get("deployments") if isinstance(body, dict) else body
        if not isinstance(rows, list):
            raise SourceError("Coolify returned an unexpected body")
        result = []
        for row in rows:
            created = _time(row.get("created_at")) if isinstance(row, dict) else None
            if created is None:
                continue
            result.append(
                Deployment(
                    service=str(app["name"]),
                    repo=_repo_of(str(app.get("git_repository", ""))),
                    commit=str(row.get("commit") or ""),
                    message=str(row.get("commit_message") or ""),
                    status=str(row.get("status") or ""),
                    created_at=created,
                    finished_at=_time(row.get("finished_at")),
                    pull_request_id=_int(row.get("pull_request_id")),
                    rollback=_flag(row.get("rollback")),
                )
            )
        return result

    async def deployments(self) -> tuple[list[Deployment], list[str]]:
        apps = await self._applications()
        answers = await asyncio.gather(*(self._app_deployments(a) for a in apps))
        deploys = [d for answer in answers if answer for d in answer]
        unavailable = [str(app["name"]) for app, answer in zip(apps, answers, strict=True) if answer is None]
        return deploys, unavailable

    def _token(self, repo: str) -> str:
        token = self._bitbucket_tokens.get(repo.lower())
        if token is None:
            raise SourceError(f"no Bitbucket token for {repo}")
        return token.get_secret_value()

    async def commits(self, repo: str, new: str, old: str, limit: int) -> list[dict[str, Any]]:
        body = await _get_json(
            self._client,
            "Bitbucket",
            f"{_BITBUCKET_API}/{repo}/commits",
            self._token(repo),
            include=new,
            exclude=old,
            pagelen=limit,
        )
        return _values(body, "Bitbucket")[:limit]

    async def diffstat(self, repo: str, new: str, old: str, limit: int) -> tuple[list[dict[str, Any]], int]:
        url = f"{_BITBUCKET_API}/{repo}/diffstat/{new}..{old}"
        body = await _get_json(self._client, "Bitbucket", url, self._token(repo), pagelen=limit, topic="false")
        values = _values(body, "Bitbucket")
        return values[:limit], _int(body.get("size", len(values)))

    async def diff(self, repo: str, new: str, old: str, path: str | None) -> tuple[str, bool]:
        """The diff text and whether it was cut at _MAX_DIFF_BYTES."""
        url = f"{_BITBUCKET_API}/{repo}/diff/{new}..{old}"
        params = {"topic": "false", **({"path": path} if path else {})}
        body = bytearray()
        try:
            async with self._client.stream(
                "GET", url, params=params, headers=_headers(self._token(repo)), timeout=_TIMEOUT_SECONDS
            ) as response:
                _check(response, "Bitbucket")
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_DIFF_BYTES:
                        break
        except httpx.HTTPError as exc:
            raise SourceError(f"Bitbucket is not reachable ({type(exc).__name__})") from exc
        return bytes(body[:_MAX_DIFF_BYTES]).decode("utf-8", errors="replace"), len(body) > _MAX_DIFF_BYTES
