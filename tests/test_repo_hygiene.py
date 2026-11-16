"""Checks on files that are not Python: they fail in CI when a secret file is tracked or a pin is dropped."""

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
TOKEN_FILE = re.compile(r"(-token|\.token)$")


def tracked_files() -> list[str]:
    result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603, S607
    if result.returncode != 0:  # an export without .git: nothing to check
        pytest.skip("not a git checkout")
    return result.stdout.splitlines()


def test_no_token_file_is_tracked():
    """Token files (deploy/ops-server/alert-token) hold secrets; this catches a `git add -f` past .gitignore."""
    tracked = [path for path in tracked_files() if TOKEN_FILE.search(path)]
    assert tracked == []


def _hujson(text: str) -> dict:
    """The example uses only // comments (own line or after a value) and trailing commas."""
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", re.sub(r"(?m)(^|\s)//.*$", "", text)))


def test_the_tailscale_acl_example_opens_exactly_the_documented_ports():
    policy = _hujson((ROOT / "deploy" / "tailscale-acl.example.hujson").read_text())

    assert set(policy["tagOwners"]) == {"tag:pikett-ops", "tag:pikett-app", "tag:pikett-ci"}
    assert set(policy["groups"]) == {"group:pikett-team"}
    ports: dict[tuple[str, str], set[str]] = {}
    for grant in policy["grants"]:
        for src in grant["src"]:
            for dst in grant["dst"]:
                ports.setdefault((src, dst), set()).update(grant["ip"])
    assert ports[("tag:pikett-app", "tag:pikett-ops")] == {f"tcp:{p}" for p in (9428, 8428, 10428, 8030, 4954)}
    assert ports[("group:pikett-team", "tag:pikett-ops")] == {"tcp:8030", "tcp:3001", "tcp:22"}
    assert ports[("group:pikett-team", "tag:pikett-app")] == {"tcp:22"}
    assert ports[("tag:pikett-ci", "tag:pikett-ops")] == {"tcp:22"}
    assert "*" not in {src for (src, _dst) in ports} | {dst for (_src, dst) in ports}
    assert policy["tests"], "the example ships tests that reject a policy that opens too much"


IMAGE_LINE = re.compile(r"^\s*image:\s*(\S+)", re.MULTILINE)


def test_every_compose_image_is_pinned_by_digest():
    unpinned = []
    for path in [ROOT / "docker-compose.yml", *sorted((ROOT / "deploy").rglob("compose*.yml"))]:
        for ref in IMAGE_LINE.findall(path.read_text()):
            if "@sha256:" not in ref and not ref.startswith("${"):  # ${OPS_IMAGE} is the image this repo builds
                unpinned.append(f"{path.relative_to(ROOT)}: {ref}")
    assert unpinned == []


def test_the_dockerfile_pins_every_base_image_by_digest():
    refs = re.findall(r"^(?:FROM|COPY --from=)\s*(?:--from=)?(\S+)", (ROOT / "Dockerfile").read_text(), re.MULTILINE)
    assert refs and [ref for ref in refs if "@sha256:" not in ref and ref != "build"] == []


def test_ci_pins_actions_by_commit_sha_and_images_by_digest():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)(.*)", text)
    assert uses
    for ref, comment in uses:
        assert re.search(r"@[0-9a-f]{40}$", ref), f"{ref} is not pinned by commit SHA"
        assert re.search(r"#\s*v\d+\.\d+\.\d+", comment), f"{ref} has no version comment"
    assert "@sha256:" in text  # the gitleaks image
