import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.agent.changes import HttpChanges, _repo_of
from app.agent.errors import SourceError
from app.agent.masking import Masker
from app.agent.ports import Deployment, Sources
from app.agent.tools import build_registry
from tests.fakes import NOW, FakeLogs, FakeMetrics, FakeTraces

NEW = "a" * 40
OLD = "b" * 40
OLDER = "c" * 40


def deploy(commit, hours_ago, service="core", status="finished", **kwargs):
    started = NOW - timedelta(hours=hours_ago)
    return Deployment(
        service=service,
        repo=kwargs.pop("repo", f"acme/{service}"),
        commit=commit,
        message=kwargs.pop("message", f"feat: change {commit[:4]}\n\nbody"),
        status=status,
        created_at=started,
        finished_at=started + kwargs.pop("took", timedelta(minutes=3)) if status == "finished" else None,
        pull_request_id=kwargs.pop("pull_request_id", 0),
        rollback=kwargs.pop("rollback", False),
    )


def commit_row(sha, message="fix: something", author="Bob B <ben@example.at>"):
    return {"hash": sha, "date": "2026-11-12T10:00:00+00:00", "author": {"raw": author}, "message": message}


@dataclass
class FakeChanges:
    deploys: list[Deployment] = field(default_factory=list)
    commit_rows: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)  # (new, old) -> commits
    diff_text: str = ""
    unavailable: list[str] = field(default_factory=list)
    commits_error: Exception | None = None
    diffstat_error: Exception | None = None
    calls: list[tuple[str, ...]] = field(default_factory=list)

    async def deployments(self):
        return list(self.deploys), list(self.unavailable)

    async def repos(self):
        return {d.service: d.repo for d in self.deploys}

    async def commits(self, repo, new, old, limit):
        self.calls.append(("commits", repo, new, old))
        if self.commits_error:
            raise self.commits_error
        return self.commit_rows.get((new, old), [])[:limit]

    async def diffstat(self, repo, new, old, limit):
        self.calls.append(("diffstat", repo, new, old))
        if self.diffstat_error:
            raise self.diffstat_error
        return [{"status": "modified", "lines_added": 4, "lines_removed": 1, "new": {"path": "src/App.java"}}], 1

    async def diff(self, repo, new, old, path):
        self.calls.append(("diff", repo, new, old, path or ""))
        return self.diff_text, False


def registry(changes: FakeChanges | None):
    sources = Sources(FakeLogs(), FakeMetrics(), FakeTraces(), changes=changes)
    return build_registry(sources, Masker(), clock=lambda: NOW)


async def call(reg, name, args):
    result = await reg.call(name, args)
    return result, (json.loads(result.text) if not result.is_error else None)


def bitbucket_calls(changes: FakeChanges) -> int:
    return sum(1 for c in changes.calls if c[0] in {"commits", "diffstat"})


def test_the_change_tools_exist_only_when_coolify_is_configured():
    assert "recent_changes" not in {d["name"] for d in registry(None).definitions()}
    names = {d["name"] for d in registry(FakeChanges()).definitions()}
    assert {"recent_changes", "get_change_diff"} <= names


async def test_a_deploy_shows_the_commits_and_files_since_the_deploy_live_before_it():
    row = commit_row(NEW, "fix: null check for anna@example.at", author="ben@example.at")
    changes = FakeChanges([deploy(NEW, 2), deploy(OLD, 30)], {(NEW, OLD): [row]})
    result, body = await call(registry(changes), "recent_changes", {})
    (core,) = body["services"]
    (entry,) = core["deploys"]  # the deploy 30 h ago is outside the default 6 h window, but it is the base
    assert entry["commit"] == NEW and entry["base_commit"] == OLD and entry["went_live"] is True
    assert entry["message"] == "feat: change aaaa" and entry["commits"][0]["commit"] == NEW
    assert entry["files"] == [{"path": "src/App.java", "status": "modified", "added": 4, "removed": 1}]
    assert core["live_at_end"]["commit"] == NEW and core["deploys_may_be_more"] is False
    assert ("commits", "acme/core", NEW, OLD) in changes.calls and "reverted_commits" not in entry
    assert "example.at" not in result.text  # summary and author go through the masker like every other result


async def test_a_rollback_lists_the_commits_it_took_back():
    changes = FakeChanges([deploy(OLD, 1, rollback=True), deploy(NEW, 9)], {(NEW, OLD): [commit_row(NEW)]})
    _, body = await call(registry(changes), "recent_changes", {})
    (entry,) = body["services"][0]["deploys"]
    assert entry["rollback"] is True and entry["commits"] == []
    assert [c["commit"] for c in entry["reverted_commits"]] == [NEW]


async def test_the_base_is_the_last_live_deploy_and_a_redeploy_changes_no_code():
    changes = FakeChanges(
        [deploy(NEW, 1), deploy(NEW, 2), deploy(OLDER, 3, status="failed"), deploy(OLD, 4)],
        {(NEW, OLD): [commit_row(NEW)]},
    )
    _, body = await call(registry(changes), "recent_changes", {})
    newest, redeploy, failed, oldest = body["services"][0]["deploys"]
    assert newest["base_commit"] == NEW and newest["same_commit_as_before"] is True and "commits" not in newest
    assert redeploy["base_commit"] == OLD and "commits" in redeploy  # the failed deploy never went live
    assert failed["went_live"] is False and failed["finished"] is None and "files" not in failed
    assert oldest["base_commit"] is None  # nothing older is known
    assert bitbucket_calls(changes) == 2  # only the redeploy with new code asked Bitbucket


async def test_a_deploy_without_a_resolved_commit_is_neither_a_change_nor_a_base():
    changes = FakeChanges([deploy(NEW, 1), deploy("HEAD", 2), deploy(OLD, 3)])
    _, body = await call(registry(changes), "recent_changes", {})
    newest, head, _ = body["services"][0]["deploys"]
    assert newest["base_commit"] == OLD and head["went_live"] is False and "commits" not in head
    assert ("commits", "acme/core", "HEAD", OLD) not in changes.calls


async def test_live_at_end_counts_from_when_a_deploy_finished():
    # Started 1 h before the end of the window but finished 2 h later: the old commit still ran at the end.
    changes = FakeChanges([deploy(NEW, 4, took=timedelta(hours=2)), deploy(OLD, 8)])
    _, body = await call(registry(changes), "recent_changes", {"start": "now-12h", "end": "now-3h"})
    core = body["services"][0]
    assert core["live_at_end"]["commit"] == OLD and [d["commit"] for d in core["deploys"]] == [NEW, OLD]


async def test_a_preview_deploy_is_neither_the_base_of_the_app_nor_live():
    changes = FakeChanges([deploy(NEW, 1), deploy(OLDER, 2, pull_request_id=7), deploy(OLD, 3)])
    _, body = await call(registry(changes), "recent_changes", {})
    app, preview, _ = body["services"][0]["deploys"]
    assert app["base_commit"] == OLD and preview["base_commit"] is None and preview["preview_pull_request"] == 7
    assert body["services"][0]["live_at_end"]["commit"] == NEW and "preview_pull_request" not in app


async def test_one_service_or_an_error_naming_the_known_ones():
    changes = FakeChanges([deploy(NEW, 1), deploy(OLD, 1, service="admin-frontend")])
    _, body = await call(registry(changes), "recent_changes", {"service": "admin-frontend"})
    assert [s["service"] for s in body["services"]] == ["admin-frontend"]
    result, _ = await call(registry(changes), "recent_changes", {"service": "cor"})
    assert result.is_error and "admin-frontend, core" in result.text


async def test_an_application_coolify_could_not_read_is_named_not_hidden():
    changes = FakeChanges([deploy(NEW, 1)], unavailable=["admin-frontend"])
    _, body = await call(registry(changes), "recent_changes", {})
    assert body["services_unavailable"] == ["admin-frontend"] and [s["service"] for s in body["services"]] == ["core"]


async def test_the_window_is_at_most_24_hours():
    result, _ = await call(registry(FakeChanges()), "recent_changes", {"start": "now-30h"})
    assert result.is_error


async def test_a_bitbucket_failure_keeps_the_deploy_and_what_else_was_found():
    changes = FakeChanges([deploy(NEW, 1), deploy(OLD, 9)], {(NEW, OLD): [commit_row(NEW)]})
    changes.diffstat_error = SourceError("Bitbucket returned 403")
    _, body = await call(registry(changes), "recent_changes", {})
    (entry,) = body["services"][0]["deploys"]
    assert entry["files_error"] == "Bitbucket returned 403" and entry["commits"][0]["commit"] == NEW


async def test_many_deploys_are_capped_and_flagged():
    shas = [f"{i:040x}" for i in range(1, 14)]
    changes = FakeChanges([deploy(sha, 0.2 + i * 0.3) for i, sha in enumerate(shas)])
    _, body = await call(registry(changes), "recent_changes", {})
    core = body["services"][0]
    assert len(core["deploys"]) == 10 and core["deploys_may_be_more"] is True
    assert bitbucket_calls(changes) == 2 * 10 + 10  # commits and files per deploy, plus the empty-commit rollback check


async def test_get_change_diff_returns_masked_lines_of_the_service_repo():
    text = "\n".join(["diff --git a/x b/x", "+mail = 'anna@example.at'", *[f"+line {i}" for i in range(500)]])
    changes = FakeChanges([deploy(NEW, 1)], diff_text=text)
    args = {"service": "core", "commit": NEW, "base_commit": OLD, "path": "x"}
    result, body = await call(registry(changes), "get_change_diff", args)
    assert body["lines"][0] == "diff --git a/x b/x" and body["lines_total"] == 502 and body["truncated"] is True
    assert ("diff", "acme/core", NEW, OLD, "x") in changes.calls and "example.at" not in result.text


@pytest.mark.parametrize(
    "args",
    [
        {"service": "core", "commit": "main", "base_commit": OLD},
        {"service": "core", "commit": NEW[:7], "base_commit": OLD},  # Bitbucket redirects short hashes
        {"service": "x", "commit": NEW, "base_commit": OLD},
        {"service": "web", "commit": NEW, "base_commit": OLD},  # not built from Bitbucket
    ],
)
async def test_get_change_diff_rejects_a_bad_commit_or_service(args):
    changes = FakeChanges([deploy(NEW, 1), deploy(NEW, 1, service="web", repo=None)])
    result, _ = await call(registry(changes), "get_change_diff", args)
    assert result.is_error


def test_repo_of_reads_ssh_and_https_urls():
    assert _repo_of("git@bitbucket.org:acme/core.git") == "acme/core"
    assert _repo_of("https://bitbucket.org/acme/admin-frontend") == "acme/admin-frontend"
    assert _repo_of("https://github.com/x/y.git") is None and _repo_of("") is None


APPS = [
    {"uuid": "u1", "name": "core", "git_repository": "git@bitbucket.org:acme/core.git"},
    {"uuid": "u2", "name": "admin-frontend", "git_repository": "git@bitbucket.org:acme/admin-frontend.git"},
    {"x": 1},
]
ROW = {
    "commit": NEW,
    "commit_message": "feat: x",
    "status": "finished",
    "created_at": "2026-11-12T10:00:00.000000Z",
    "finished_at": "2026-11-12T10:03:00.000000Z",
    "pull_request_id": "0",
    "rollback": "False",
}


def handler(request: httpx.Request) -> httpx.Response:
    assert request.headers["Authorization"].startswith("Bearer ")
    path, params = request.url.path, request.url.params
    if path == "/api/v1/applications":
        return httpx.Response(200, json=APPS)
    if path == "/api/v1/deployments/applications/u1":
        assert params["take"] == "20"
        return httpx.Response(200, json={"count": 2, "deployments": [ROW, {"status": "queued"}]})
    if path == "/api/v1/deployments/applications/u2":
        return httpx.Response(500, text="boom token=secret-echo")
    if path == "/2.0/repositories/acme/core/commits":
        assert (params["include"], params["exclude"], params["pagelen"]) == (NEW, OLD, "5")
        assert request.headers["Authorization"] == "Bearer repo-token"
        return httpx.Response(200, json={"values": [{"hash": NEW}]})
    if path == "/2.0/repositories/acme/core/diffstat/" + f"{NEW}..{OLD}":
        assert params["topic"] == "false" and params["pagelen"] == "5"
        return httpx.Response(200, json={"values": [{"status": "added"}], "size": 3})
    if path == "/2.0/repositories/acme/core/diff/" + f"{NEW}..{OLD}":
        assert params["topic"] == "false" and params["path"] == "src/x"
        return httpx.Response(200, text="d" * 1_500_000)
    if path == "/2.0/repositories/acme/moved/commits":
        return httpx.Response(302, headers={"Location": "https://api.bitbucket.org/elsewhere"})
    if path == "/2.0/repositories/acme/odd/commits":
        return httpx.Response(200, json=["not", "a", "page"])
    return httpx.Response(404, text="token=secret-echo")


def http_changes() -> HttpChanges:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tokens = {
        "acme/core": SecretStr("repo-token"),
        "acme/odd": SecretStr("t"),
        "acme/moved": SecretStr("t"),
    }
    return HttpChanges(client, "https://coolify.test/", SecretStr("api-token"), tokens)


async def test_http_changes_reads_the_coolify_shape_and_names_an_app_it_could_not_read():
    (d,), unavailable = await http_changes().deployments()  # the queued row has no created_at and is skipped
    assert (d.service, d.repo, d.commit, d.status, d.pull_request_id, d.rollback) == (
        "core",
        "acme/core",
        NEW,
        "finished",
        0,
        False,
    )
    assert d.finished_at is not None and d.finished_at - d.created_at == timedelta(minutes=3)
    assert unavailable == ["admin-frontend"]
    assert await http_changes().repos() == {"core": "acme/core", "admin-frontend": "acme/admin-frontend"}


async def test_http_changes_asks_bitbucket_for_the_two_dot_diff_with_the_repo_token():
    changes = http_changes()
    assert await changes.commits("acme/core", NEW, OLD, 5) == [{"hash": NEW}]
    assert await changes.diffstat("acme/core", NEW, OLD, 5) == ([{"status": "added"}], 3)
    text, cut = await changes.diff("acme/core", NEW, OLD, "src/x")
    assert cut is True and len(text) == 1_000_000  # a huge diff is not read to the end


async def test_http_changes_errors_say_what_failed_but_never_show_bodies_or_tokens():
    changes = http_changes()
    with pytest.raises(SourceError) as error:
        await changes.diff("acme/core", OLD, NEW, None)
    assert "404" in str(error.value) and "secret" not in str(error.value)
    with pytest.raises(SourceError, match="unexpected body"):
        await changes.commits("acme/odd", NEW, OLD, 5)
    with pytest.raises(SourceError, match="returned 302"):
        await changes.commits("acme/moved", NEW, OLD, 5)
    with pytest.raises(SourceError, match="no Bitbucket token"):
        await changes.commits("acme/other", NEW, OLD, 5)


def test_a_zone_less_coolify_timestamp_is_read_as_utc():
    from app.agent.changes import _time

    parsed = _time("2026-11-14 10:00:00")
    assert parsed is not None and parsed.utcoffset() is not None


async def test_a_deploy_that_started_before_the_window_but_finished_inside_it_is_listed():
    changes = FakeChanges([deploy(NEW, 6.05, took=timedelta(minutes=10)), deploy(OLD, 20)])
    _, body = await call(registry(changes), "recent_changes", {"start": "now-6h"})
    assert [d["commit"] for d in body["services"][0]["deploys"]] == [NEW]


async def test_a_full_history_that_starts_inside_the_window_is_flagged_as_cut():
    deploys = [deploy(f"{i:040x}", i / 10) for i in range(1, 21)]  # 20 deploys, the oldest 2 h ago
    _, body = await call(registry(FakeChanges(deploys)), "recent_changes", {"start": "now-6h"})
    assert body["services"][0]["history_cut_before_window"] is True


async def test_a_commit_row_of_an_unexpected_shape_keeps_the_rest_of_the_answer():
    changes = FakeChanges([deploy(NEW, 1), deploy(OLD, 2)], commit_rows={(NEW, OLD): [{"hash": NEW, "author": "ben"}]})
    _, body = await call(registry(changes), "recent_changes", {})
    newest = body["services"][0]["deploys"][0]
    assert newest["commits_error"] == "unexpected commit data" and newest["files_total"] == 1
