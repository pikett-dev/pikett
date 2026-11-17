"""agent.sh: what ALLOY_LOCAL_DIR copies, and what it refuses before it copies anything."""

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "deploy" / "app-host" / "agent.sh"


def deploy(local_dir: Path | None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DRY_RUN": "1", "OPS_SERVER": "100.64.0.10", "TEST_HOST": "app-1"}
    env.pop("ALLOY_LOCAL_DIR", None)
    if local_dir is not None:
        env["ALLOY_LOCAL_DIR"] = str(local_dir)
    return subprocess.run(["bash", str(SCRIPT), "deploy"], env=env, capture_output=True, text=True)  # noqa: S603, S607


def rsync_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith("+ rsync")]


def test_without_the_variable_only_the_shipped_files_are_copied() -> None:
    result = deploy(None)
    assert result.returncode == 0, result.stderr
    lines = rsync_lines(result.stdout)
    assert len(lines) == 1
    assert "--delete" not in lines[0], "a run without the variable keeps what is on the server"
    assert "--exclude *.env" in lines[0], ".env and secrets.env on the server are never touched"


def test_local_files_are_copied_and_only_they_are_deleted(tmp_path: Path) -> None:
    (tmp_path / "local-apps.alloy").write_text("")
    (tmp_path / "local-db.alloy").write_text("")
    result = deploy(tmp_path)
    assert result.returncode == 0, result.stderr
    lines = rsync_lines(result.stdout)
    assert len(lines) == 2
    second = lines[1]
    assert "--delete" in second
    assert second.index("--include local-*.alloy") < second.index("--exclude *"), "the include has to come first"
    assert second.endswith(f"{tmp_path}/ root@app-1:/opt/ops-agent/alloy/")


def test_an_empty_folder_is_allowed(tmp_path: Path) -> None:
    assert deploy(tmp_path).returncode == 0


def test_other_names_are_refused_before_anything_is_copied(tmp_path: Path) -> None:
    (tmp_path / "local-ok.alloy").write_text("")
    (tmp_path / "config.alloy").write_text("")
    result = deploy(tmp_path)
    assert result.returncode == 1
    assert "local-*.alloy" in result.stderr
    assert rsync_lines(result.stdout) == []


def test_a_subfolder_is_refused(tmp_path: Path) -> None:
    (tmp_path / "local-sub.alloy").mkdir()
    result = deploy(tmp_path)
    assert result.returncode == 1
    assert rsync_lines(result.stdout) == []


def test_a_missing_folder_is_refused(tmp_path: Path) -> None:
    result = deploy(tmp_path / "missing")
    assert result.returncode == 1
    assert "not a directory" in result.stderr
