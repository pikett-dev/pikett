"""The shipped rule files, the Alloy files and the compose mount, checked with the tools that will read them.

Needs Docker, like the tests with a real Postgres. The images are the ones pinned in the compose files, so there is
one pin to update."""

import functools
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
OPS_COMPOSE = ROOT / "deploy" / "ops-server" / "compose.yml"
APP_COMPOSE = ROOT / "deploy" / "app-host" / "compose.yml"
RULES = ROOT / "deploy" / "vmalert" / "rules"
ALLOY = ROOT / "deploy" / "app-host" / "alloy"


@functools.cache
def pinned(compose: Path, repository: str) -> str:
    match = re.search(rf"image:\s*({re.escape(repository)}:\S+)", compose.read_text(encoding="utf-8"))
    assert match, f"no {repository} image in {compose}"
    return match.group(1)


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True)  # noqa: S603, S607


needs_docker = pytest.mark.skipif(shutil.which("docker") is None, reason="needs Docker")


def vmalert_check(directory: Path) -> subprocess.CompletedProcess[str]:
    image = pinned(OPS_COMPOSE, "victoriametrics/vmalert")
    return docker("run", "--rm", "-v", f"{directory}:/check:ro", image, "-dryRun", "-rule=/check/*.yml")


def alloy_validate(config_dir: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    args = [item for key, value in env.items() for item in ("-e", f"{key}={value}")]
    image = pinned(APP_COMPOSE, "grafana/alloy")
    return docker(
        "run", "--rm", *args, "-v", f"{config_dir}:/etc/alloy:ro", image,
        "validate", "--stability.level=public-preview", "/etc/alloy",
    )  # fmt: skip


@needs_docker
def test_vmalert_accepts_the_shipped_rules_refuses_a_broken_one_and_lets_a_file_be_switched_off(tmp_path: Path) -> None:
    result = vmalert_check(RULES)
    assert result.returncode == 0, result.stdout + result.stderr
    candidate = tmp_path / "cand"
    shutil.copytree(RULES, candidate)
    (candidate / "own.yml").write_text("groups:\n- name: x\n  rules:\n  - alert: A\n    expr: up ==\n")
    assert vmalert_check(candidate).returncode != 0
    (candidate / "own.yml").unlink()
    # `groups: []` in a file of the same name as a shipped one is how an installation switches that file off.
    (candidate / "apps.yml").write_text("groups: []\n")
    assert vmalert_check(candidate).returncode == 0
    # The glob is never empty in a deploy, because the shipped files are always there; on its own it is fatal.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert vmalert_check(empty).returncode != 0


@needs_docker
def test_the_alloy_files_load_together_and_the_examples_find_the_shipped_components(tmp_path: Path) -> None:
    """One directory, as the agent loads it: config.alloy plus the examples copied as local-*.alloy."""
    config_dir = tmp_path / "alloy"
    config_dir.mkdir()
    shutil.copy(ALLOY / "config.alloy", config_dir)
    for example in (ALLOY / "examples").glob("local-*.alloy"):
        shutil.copy(example, config_dir)
    assert len(list(config_dir.glob("local-*.alloy"))) == 2
    env = {
        "OPS_SERVER": "10.0.0.1",
        "HOST_NAME": "app-1",
        "APP_ACME_API_METRICS_TOKEN": "token",
        "PG_ACME_DSN": "postgresql://user:password@db:5432/app?sslmode=disable",
    }
    result = alloy_validate(config_dir, env)
    assert result.returncode == 0, result.stdout + result.stderr
    # A reference to a component that does not exist is an error, so a file that passes does reach remote_write.
    (config_dir / "local-bad.alloy").write_text(
        'prometheus.scrape "x" {\n  targets = []\n  forward_to = [prometheus.remote_write.nope.receiver]\n}\n'
    )
    assert alloy_validate(config_dir, env).returncode != 0


def test_the_examples_are_not_in_the_directory_alloy_loads() -> None:
    """Alloy ignores subdirectories; a loose local-*.alloy next to config.alloy would be loaded unasked."""
    assert [p.name for p in ALLOY.glob("*.alloy")] == ["config.alloy"]


def test_vmalert_mounts_rules_live_and_fails_when_it_is_missing() -> None:
    compose = yaml.safe_load(OPS_COMPOSE.read_text(encoding="utf-8"))
    mounts = [v for v in compose["services"]["vmalert"]["volumes"] if isinstance(v, dict) and v["target"] == "/rules"]
    assert mounts, "the rules mount must use the long form"
    mount = mounts[0]
    assert mount["source"] == "../vmalert/rules.live"
    assert mount["read_only"] is True
    assert mount["bind"]["create_host_path"] is False


@needs_docker
def test_compose_refuses_to_start_without_rules_live(tmp_path: Path) -> None:
    """Runs `docker compose up` for vmalert only, in a copy of the ops-server directory without rules.live."""
    work = tmp_path / "deploy"
    shutil.copytree(
        ROOT / "deploy" / "ops-server", work / "ops-server", ignore=shutil.ignore_patterns("catalog", ".DS_Store")
    )
    (work / "vmalert").mkdir()
    (work / "ops-server" / "alert-token").write_text("t")
    env_file = tmp_path / "test.env"
    env_file.write_text(
        "TAILSCALE_IP=127.0.0.1\nOPS_IMAGE=x\nOPS_DB_PASSWORD=x\nKUMA_DB_PASSWORD=x\nKUMA_DB_ROOT_PASSWORD=x\n"
    )
    base = [
        "docker",
        "compose",
        "-p",
        "pikett-test-rules",
        "--env-file",
        str(env_file),
        "-f",
        str(work / "ops-server" / "compose.yml"),
    ]
    image = pinned(OPS_COMPOSE, "victoriametrics/vmalert")
    # the compose call below runs with --pull never
    if docker("image", "inspect", image).returncode != 0:
        docker("pull", "-q", image)
    missing = subprocess.run(  # noqa: S603
        [*base, "up", "--no-deps", "--no-build", "--pull", "never", "vmalert"],
        capture_output=True,
        text=True,
        cwd=work / "ops-server",
    )
    subprocess.run([*base, "down", "--remove-orphans"], capture_output=True, cwd=work / "ops-server")  # noqa: S603
    assert missing.returncode != 0
    assert "rules.live" in missing.stderr
