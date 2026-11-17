"""dev/alert.sh: where the bearer token comes from."""

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "dev" / "alert.sh"


def run(tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    """Run the script with a fake curl in front, which prints its arguments instead of sending them."""
    fake = tmp_path / "bin" / "curl"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    base = {k: v for k, v in os.environ.items() if k not in {"ALERT_TOKEN", "ALERT_TOKEN_FILE", "OPS_URL"}}
    base["PATH"] = f"{fake.parent}:{base['PATH']}"
    command = ["bash", str(SCRIPT), "fire", "P2"]
    return subprocess.run(command, env={**base, **env}, capture_output=True, text=True)  # noqa: S603, S607


def test_the_token_is_read_from_the_file(tmp_path: Path) -> None:
    token_file = tmp_path / "alert-token"
    token_file.write_text("file-token-value\r\n")  # a stray CR or newline must not end up in the header
    result = run(tmp_path, OPS_URL="http://ops-server:8030", ALERT_TOKEN_FILE=str(token_file))
    assert result.returncode == 0, result.stderr
    assert "Authorization: Bearer file-token-value" in result.stdout
    assert "note:" not in result.stderr


def test_the_environment_wins_over_the_file(tmp_path: Path) -> None:
    token_file = tmp_path / "alert-token"
    token_file.write_text("file-token-value")
    env = {"OPS_URL": "http://x:8030", "ALERT_TOKEN": "env-token", "ALERT_TOKEN_FILE": str(token_file)}
    result = run(tmp_path, **env)
    assert result.returncode == 0, result.stderr
    assert "Bearer env-token" in result.stdout
    assert "file-token-value" not in result.stdout


def test_an_unreadable_file_stops_before_anything_is_sent(tmp_path: Path) -> None:
    result = run(tmp_path, OPS_URL="http://x:8030", ALERT_TOKEN_FILE=str(tmp_path / "missing"))
    assert result.returncode == 1
    assert "ALERT_TOKEN_FILE" in result.stderr
    assert result.stdout == ""


def test_a_remote_server_without_any_token_says_so(tmp_path: Path) -> None:
    result = run(tmp_path, OPS_URL="http://x:8030")
    assert result.returncode == 0
    assert "note:" in result.stderr
    assert "Authorization" not in result.stdout
