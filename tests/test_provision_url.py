"""What provision.sh pipeline accepts as OPS_REPO_URL: an SSH URL, or an https URL without credentials."""

import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "deploy" / "ops-server" / "provision.sh"


def parse(url: str) -> subprocess.CompletedProcess[str]:
    """Runs parse_repo_url from the marked block of the script; prints `<transport> <host>` when it accepts the URL."""
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"# --- repo_url:.*?# --- end repo_url ---", text, re.DOTALL)
    assert block, "the markers of the repo_url block are gone"
    snippet = f'set -euo pipefail; {block.group(0)}\nparse_repo_url "$1" && echo "$repo_transport $repo_host"'
    return subprocess.run(["bash", "-c", snippet, "bash", url], capture_output=True, text=True)  # noqa: S603, S607


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git@github.com:acme/api.git", "ssh github.com"),
        ("ssh://git@git.example.com:2222/acme/api.git", "ssh git.example.com"),
        ("https://github.com/pikett-dev/pikett.git", "https github.com"),
        ("https://git.example.com:8443/acme/api.git", "https git.example.com"),
    ],
)
def test_an_ssh_url_and_an_https_url_are_accepted(url: str, expected: str) -> None:
    result = parse(url)
    assert (result.returncode, result.stdout.strip()) == (0, expected), result.stderr


@pytest.mark.parametrize(
    "url",
    [
        "https://alice@github.com/acme/api.git",
        "https://alice:secret@github.com/acme/api.git",
        "https://x-token-auth:abc123@git.example.com/acme/api.git",
        "http://alice:secret@github.com/acme/api.git",
    ],
)
def test_an_https_url_with_credentials_is_refused(url: str) -> None:
    result = parse(url)
    assert result.returncode != 0
    assert "must not carry credentials" in result.stderr


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://github.com/acme/my repo.git",
        "git@github.com:acme/my repo.git",
        " https://github.com/acme/api.git",
        "http://github.com/acme/api.git",
        "https://github.com",
        "https://github.com/acme/api'.git",
        'https://github.com/acme/api".git',
        "/srv/git/api.git",
        "https://github.com/acme/api.git?access_token=abc123",
        "https://github.com/acme/api.git#token",
        "ssh://git:secret@git.example.com/acme/api.git",
        "alice:secret@github.com:acme/api.git",
        "HTTPS://alice:secret@github.com/acme/api.git",
        "git@-oProxyCommand:acme/api.git",
        "https://-x/acme/api.git",
    ],
)
def test_any_other_url_is_refused(url: str) -> None:
    result = parse(url)
    assert result.returncode != 0
    assert "OPS_REPO_URL must be" in result.stderr
