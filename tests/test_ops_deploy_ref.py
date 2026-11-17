"""What ops-deploy.sh accepts from the SSH command: a release tag or a full commit hash, both only when on main."""

import os
import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "deploy" / "ops-server" / "ops-deploy.sh"
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True, text=True)  # noqa: S603, S607
    return result.stdout.strip()


def commit(cwd: Path, name: str) -> str:
    (cwd / name).write_text(name)
    git(cwd, "add", name)
    git(cwd, "commit", "-q", "-m", name)
    return git(cwd, "rev-parse", "HEAD")


@pytest.fixture
def checkout(tmp_path: Path) -> dict[str, str]:
    """A clone of an origin with main, a lightweight and an annotated release tag, and a tag only on a side branch."""
    origin = tmp_path / "origin"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    first = commit(origin, "one")
    git(origin, "tag", "v1.2.3")
    second = commit(origin, "two")
    git(origin, "tag", "-a", "v2.0.0", "-m", "annotated")
    git(origin, "checkout", "-q", "-b", "side")
    side = commit(origin, "side")
    git(origin, "tag", "v9.9.9")
    git(origin, "checkout", "-q", "main")
    repo = tmp_path / "repo"
    git(tmp_path, "clone", "-q", str(origin), str(repo))
    fetch(str(repo))
    return {"origin": str(origin), "repo": str(repo), "first": first, "second": second, "side": side}


def run_block(repo: str, snippet: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Runs `snippet` after the block between the markers of the script, with `repo` set to the checkout."""
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"# --- resolve_ref:.*?# --- end resolve_ref ---", text, re.DOTALL)
    assert block, "the markers of the resolve_ref block are gone"
    return subprocess.run(  # noqa: S603
        ["bash", "-c", f'set -euo pipefail; repo="$1"; {block.group(0)}\n{snippet}', "bash", repo, *args],  # noqa: S607
        env=GIT_ENV,
        capture_output=True,
        text=True,
    )


def fetch(repo: str) -> None:
    """The fetch step of the script: main and the release tags, as origin has them now."""
    result = run_block(repo, "fetch_refs")
    assert result.returncode == 0, result.stderr


def resolve(repo: str, ref: str) -> subprocess.CompletedProcess[str]:
    return run_block(repo, 'resolve_ref "$2"', ref)


def test_a_release_tag_resolves_to_its_commit(checkout: dict[str, str]) -> None:
    result = resolve(checkout["repo"], "v1.2.3")
    assert (result.returncode, result.stdout.strip()) == (0, checkout["first"])


def test_an_annotated_tag_resolves_to_the_commit_not_the_tag_object(checkout: dict[str, str]) -> None:
    result = resolve(checkout["repo"], "v2.0.0")
    assert (result.returncode, result.stdout.strip()) == (0, checkout["second"])


def test_a_full_hash_on_main_is_accepted(checkout: dict[str, str]) -> None:
    result = resolve(checkout["repo"], checkout["first"])
    assert (result.returncode, result.stdout.strip()) == (0, checkout["first"])


def test_a_hash_that_is_not_on_main_is_refused(checkout: dict[str, str]) -> None:
    result = resolve(checkout["repo"], checkout["side"])
    assert result.returncode != 0
    assert "not part of origin/main" in result.stderr


def test_a_tag_on_a_side_branch_is_refused(checkout: dict[str, str]) -> None:
    result = resolve(checkout["repo"], "v9.9.9")
    assert result.returncode != 0
    assert "not part of origin/main" in result.stderr


def test_a_tag_that_does_not_exist_is_refused(checkout: dict[str, str]) -> None:
    result = resolve(checkout["repo"], "v3.0.0")
    assert result.returncode != 0
    assert "does not exist" in result.stderr


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "main",
        "v1.2",
        "v1.2.3-rc1",
        "1.2.3",
        "v1.2.3; touch /tmp/pwned",
        "v1.2.3 v2.0.0",
        "$(id)",
        "../v1.2.3",
        "abc123",
        "A" * 40,
        "a" * 39,
        "a" * 41,
        "refs/tags/v1.2.3",
    ],
)
def test_anything_but_a_release_tag_or_a_full_hash_is_refused(checkout: dict[str, str], ref: str) -> None:
    result = resolve(checkout["repo"], ref)
    assert result.returncode != 0
    assert "expected a release tag" in result.stderr


def test_a_tag_that_origin_moved_follows_origin(checkout: dict[str, str]) -> None:
    git(Path(checkout["origin"]), "tag", "-f", "v1.2.3", checkout["second"])
    fetch(checkout["repo"])
    result = resolve(checkout["repo"], "v1.2.3")
    assert (result.returncode, result.stdout.strip()) == (0, checkout["second"])


def test_a_tag_that_origin_deleted_can_no_longer_be_deployed(checkout: dict[str, str]) -> None:
    git(Path(checkout["origin"]), "tag", "-d", "v1.2.3")
    fetch(checkout["repo"])
    result = resolve(checkout["repo"], "v1.2.3")
    assert result.returncode != 0
    assert "does not exist in origin" in result.stderr


def test_a_tag_made_on_the_server_itself_is_ignored(checkout: dict[str, str]) -> None:
    git(Path(checkout["repo"]), "tag", "v5.0.0", checkout["first"])
    result = resolve(checkout["repo"], "v5.0.0")
    assert result.returncode != 0
    assert "does not exist in origin" in result.stderr


def test_a_local_tag_that_disagrees_with_origin_does_not_block_the_fetch(checkout: dict[str, str]) -> None:
    git(Path(checkout["repo"]), "tag", "-f", "v1.2.3", checkout["second"])  # a stale or hand-made local tag
    fetch(checkout["repo"])  # must not fail: that would block every deploy, hash deploys included
    assert resolve(checkout["repo"], checkout["first"]).returncode == 0
    result = resolve(checkout["repo"], "v1.2.3")
    assert (result.returncode, result.stdout.strip()) == (0, checkout["first"])  # origin's version of the tag
