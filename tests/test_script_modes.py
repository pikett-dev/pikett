import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def tracked_files() -> list[tuple[str, str]]:
    """(mode, path) of every file git tracks. The recorded mode counts, not the one on this disk: that is what a clone
    and a `rsync` of a checkout carry to a server."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    listing = subprocess.run(  # noqa: S603
        ["git", "ls-files", "-s"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [(line.split()[0], line.split("\t", 1)[1]) for line in listing.splitlines()]


def test_every_script_with_a_shebang_is_executable_in_git():
    """The docs run these as `deploy/runner/install.sh` and `deploy/ops-server/provision.sh`; mode 644 makes that fail
    with "Permission denied"."""
    not_executable = [
        path
        for mode, path in tracked_files()
        if mode == "100644" and (ROOT / path).is_file() and (ROOT / path).read_bytes()[:2] == b"#!"
    ]

    assert not_executable == []
