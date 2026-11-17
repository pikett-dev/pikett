"""The own-rules part of ops-deploy.sh: the SSH command, the tar on stdin, the candidate rule set and the sync."""

import gzip
import io
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

from tests.test_ops_deploy_ref import GIT_ENV, SCRIPT, git


def run_block(
    snippet: str, *args: str, stdin: bytes = b"", cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Runs `snippet` after the `rules` block of the script; the first argument is the repo variable."""
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"# --- rules:.*?# --- end rules ---", text, re.DOTALL)
    assert block, "the markers of the rules block are gone"
    return subprocess.run(  # noqa: S603
        ["bash", "-c", f'set -euo pipefail; repo="${{1:-}}"; {block.group(0)}\n{snippet}', "bash", *args],  # noqa: S607
        env=GIT_ENV,
        input=stdin,
        capture_output=True,
        cwd=cwd,
    )


def make_tar(members: dict[str, bytes | tarfile.TarInfo]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in members.items():
            if isinstance(content, tarfile.TarInfo):
                content.name = name
                tar.addfile(content)
                continue
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def receive(tmp_path: Path, data: bytes) -> tuple[subprocess.CompletedProcess[bytes], Path]:
    dest = tmp_path / "dest"
    dest.mkdir()
    return run_block('receive_rules "$2"', "", str(dest), stdin=data), dest


def names(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


# ---- the SSH command ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("v1.2.3", "v1.2.3|0"),
        ("v1.2.3 rules", "v1.2.3|1"),
        ("a" * 40 + " rules", "a" * 40 + "|1"),
        ("v1.2.3 rules ", "v1.2.3 rules |0"),  # left as it is; valid_ref refuses it
        ("v1.2.3 other", "v1.2.3 other|0"),
        ("", "|0"),
    ],
)
def test_the_command_is_a_ref_with_an_optional_rules_word(command: str, expected: str) -> None:
    result = run_block('parse_command "$2"; printf "%s|%s" "$ref" "$with_rules"', "", command)
    assert result.stdout.decode() == expected


@pytest.mark.parametrize("command", ["v1.2.3 rules ", "v1.2.3 other", "v1.2.3 rules rules", "v1.2.3; id", ""])
def test_anything_but_a_ref_and_the_rules_word_is_refused(command: str) -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    ref_block = re.search(r"# --- resolve_ref:.*?# --- end resolve_ref ---", text, re.DOTALL)
    rules_block = re.search(r"# --- rules:.*?# --- end rules ---", text, re.DOTALL)
    assert ref_block and rules_block
    snippet = f'{ref_block.group(0)}\n{rules_block.group(0)}\nparse_command "$1"; valid_ref "$ref"'
    result = subprocess.run(["bash", "-c", snippet, "bash", command], capture_output=True)  # noqa: S603, S607
    assert result.returncode == 1


# ---- the tar on stdin -----------------------------------------------------------------------------------------


def test_a_tar_of_yml_files_is_unpacked(tmp_path: Path) -> None:
    result, dest = receive(
        tmp_path, make_tar({"./": tarfile.TarInfo(), "./a.yml": b"groups: []\n", "b.yml": b"groups: []\n"})
    )
    assert result.returncode == 0, result.stderr
    assert names(dest) == ["a.yml", "b.yml"]


def test_an_empty_stream_is_refused_so_a_failed_client_cannot_wipe_the_rules(tmp_path: Path) -> None:
    result, dest = receive(tmp_path, b"")
    assert result.returncode == 1
    assert b"empty" in result.stderr


def test_a_tar_with_only_the_folder_entry_means_no_own_rules(tmp_path: Path) -> None:
    result, dest = receive(tmp_path, make_tar({"./": tarfile.TarInfo()}))
    assert result.returncode == 0, result.stderr
    assert names(dest) == []


def test_a_compressed_tar_is_refused(tmp_path: Path) -> None:
    result, dest = receive(tmp_path, gzip.compress(make_tar({"a.yml": b"x"})))
    assert result.returncode == 1
    assert b"uncompressed" in result.stderr
    assert names(dest) == []


def test_a_tar_over_the_size_limit_is_refused(tmp_path: Path) -> None:
    result, dest = receive(tmp_path, make_tar({"big.yml": b"#" * (1024 * 1024 + 1)}))
    assert result.returncode == 1
    assert b"larger" in result.stderr
    assert names(dest) == []


def test_a_tar_with_too_many_entries_is_refused(tmp_path: Path) -> None:
    result, dest = receive(tmp_path, make_tar({f"r{i}.yml": b"x" for i in range(101)}))
    assert result.returncode == 1
    assert b"more than" in result.stderr
    assert names(dest) == []


def _link(kind: bytes, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo()
    info.type = kind
    info.linkname = target
    return info


@pytest.mark.parametrize(
    "members",
    [
        {"sub/a.yml": b"x"},
        {"../a.yml": b"x"},
        {"/etc/a.yml": b"x"},
        {"a.yaml": b"x"},
        {"a.txt": b"x"},
        {".hidden.yml": b"x"},
        {"a b.yml": b"x"},
        {"sub/": tarfile.TarInfo()},
        {"a.yml": _link(tarfile.SYMTYPE, "/etc/passwd")},
        {"a.yml": _link(tarfile.LNKTYPE, "b.yml")},
        {"a.yml": _link(tarfile.CHRTYPE, "")},
    ],
    ids=["subdir", "dotdot", "absolute", "yaml", "txt", "hidden", "space", "dir", "symlink", "hardlink", "device"],
)
def test_a_tar_with_anything_but_top_level_yml_files_is_refused(tmp_path: Path, members: dict) -> None:
    if "sub/" in members:
        members["sub/"].type = tarfile.DIRTYPE
    result, dest = receive(tmp_path, make_tar(members))
    assert result.returncode == 1, result.stderr
    assert names(dest) == []


def test_garbage_is_not_a_tar(tmp_path: Path) -> None:
    result, dest = receive(tmp_path, b"this is not a tar" * 100)
    assert result.returncode == 1
    assert names(dest) == []


# ---- the candidate and the sync -------------------------------------------------------------------------------


@pytest.fixture
def release(tmp_path: Path) -> tuple[str, str]:
    """A repository whose commit holds shipped rules; the working tree is changed afterwards to something else."""
    repo = tmp_path / "repo"
    rules = repo / "deploy" / "vmalert" / "rules"
    rules.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (rules / "apps.yml").write_text("shipped apps")
    (rules / "host.yml").write_text("shipped host")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "release")
    sha = git(repo, "rev-parse", "HEAD")
    (rules / "apps.yml").write_text("edited in the working tree")  # must not reach the candidate
    return str(repo), sha


def test_the_candidate_holds_the_shipped_rules_of_the_commit_and_the_own_ones_by_name(
    tmp_path: Path, release: tuple[str, str]
) -> None:
    repo, sha = release
    own, cand = tmp_path / "own", tmp_path / "cand"
    own.mkdir()
    cand.mkdir()
    (own / "apps.yml").write_text("own apps")  # replaces the shipped file of the same name
    (own / "extra.yml").write_text("own extra")
    result = run_block('build_candidate "$2" "$3" "$4"', repo, sha, str(own), str(cand))
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_text() for p in cand.iterdir()} == {
        "apps.yml": "own apps",
        "host.yml": "shipped host",
        "extra.yml": "own extra",
    }


def test_the_candidate_without_own_rules_is_the_shipped_set(tmp_path: Path, release: tuple[str, str]) -> None:
    repo, sha = release
    cand = tmp_path / "cand"
    cand.mkdir()
    for own in (tmp_path / "missing", tmp_path / "empty"):
        (tmp_path / "empty").mkdir(exist_ok=True)
        result = run_block('build_candidate "$2" "$3" "$4"', repo, sha, str(own), str(cand))
        assert result.returncode == 0, result.stderr
        assert {p.name: p.read_text() for p in cand.iterdir()} == {
            "apps.yml": "shipped apps",
            "host.yml": "shipped host",
        }


def test_sync_makes_the_target_equal_to_the_source_in_place(tmp_path: Path) -> None:
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "new.yml").write_text("new")
    (src / "same.yml").write_text("updated")
    (dst / "same.yml").write_text("old")
    (dst / "gone.yml").write_text("old")
    (dst / "other.txt").write_text("not a rule file")
    inode = dst.stat().st_ino
    result = run_block('sync_rules "$2" "$3"', "", str(src), str(dst))
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_text() for p in dst.iterdir()} == {
        "new.yml": "new",
        "same.yml": "updated",
        "other.txt": "not a rule file",
    }
    assert dst.stat().st_ino == inode, "the directory must stay the same one: a bind mount follows the inode"


def test_sync_creates_a_missing_target_and_empties_one_for_an_empty_source(tmp_path: Path) -> None:
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    (src / "a.yml").write_text("a")
    assert run_block('sync_rules "$2" "$3"', "", str(src), str(dst)).returncode == 0
    assert names(dst) == ["a.yml"]
    (src / "a.yml").unlink()
    assert run_block('sync_rules "$2" "$3"', "", str(src), str(dst)).returncode == 0
    assert names(dst) == []


def test_vmalert_image_is_read_from_the_compose_file_of_the_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "deploy" / "ops-server").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    shipped = SCRIPT.parent / "compose.yml"
    (repo / "deploy" / "ops-server" / "compose.yml").write_text(shipped.read_text(encoding="utf-8"))
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "x")
    result = run_block("vmalert_image HEAD", str(repo), cwd=repo)
    image = result.stdout.decode().strip()
    assert re.fullmatch(r"victoriametrics/vmalert:v[0-9.]+@sha256:[0-9a-f]{64}", image), image


# ---- the order of the steps -----------------------------------------------------------------------------------


def test_the_rules_are_checked_before_anything_on_the_server_changes() -> None:
    """A rule that vmalert refuses must stop the deploy before the checkout, the sync and the build."""
    text = SCRIPT.read_text(encoding="utf-8")
    main = text[text.index("# --- end rules ---") :]
    check = main.index("rules_check ")
    for later in ('git -C "$repo" checkout', "sync_rules", "docker build", "docker compose up"):
        assert check < main.index(later), later
    # The stdin of the SSH command is read before the lock, so a malformed tar is refused without waiting.
    assert main.index("receive_rules ") < main.index("flock")
