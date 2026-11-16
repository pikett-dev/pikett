from datetime import timedelta

import httpx
import pytest

from app.security import overview
from app.security.images import (
    DOCKER_HUB,
    CoolifyRelease,
    HttpRegistry,
    ImageRef,
    ImageUpdatesCheck,
    RegistryError,
    note_lines,
    parse_ref,
    version_key,
)
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import EN
from tests.security_helpers import report

HOST = "app-1"
OLD, NEW = "sha256:" + "a" * 64, "sha256:" + "b" * 64


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("postgres:18", ImageRef(DOCKER_HUB, "library/postgres", "18", False)),
        ("postgres", ImageRef(DOCKER_HUB, "library/postgres", "latest", False)),
        ("grafana/alloy:v1.20.1", ImageRef(DOCKER_HUB, "grafana/alloy", "v1.20.1", False)),
        ("docker.io/louislam/uptime-kuma:2", ImageRef(DOCKER_HUB, "louislam/uptime-kuma", "2", False)),
        ("ghcr.io/coollabsio/coolify:4.0.0", ImageRef("ghcr.io", "coollabsio/coolify", "4.0.0", False)),
        ("localhost:5000/app", ImageRef("localhost:5000", "app", "latest", False)),
        (f"redis@{OLD}", ImageRef(DOCKER_HUB, "library/redis", "latest", True)),
    ],
)
def test_image_references_follow_dockers_rules(ref, expected):
    assert parse_ref(ref) == expected


class FakeRegistry:
    def __init__(self, digests: dict[str, str | Exception]):
        self.digests = digests
        self.asked: list[str] = []

    async def digest(self, ref):
        key = f"{ref.repository}:{ref.tag}"
        self.asked.append(key)
        result = self.digests[key]
        if isinstance(result, Exception):
            raise result
        return result


class FakeCoolify:
    def __init__(self, current="v4.0.0-beta.420", latest="v4.0.0-beta.421", error=None):
        self._current, self._latest, self._error = current, latest, error

    async def current(self):
        if self._error:
            raise self._error
        return self._current

    async def latest(self):
        notes = "## Changes\n- Fix **proxy** restart ([#123](https://github.com/x))\n- New S3 backups\nplain text"
        return CoolifyRelease(self._latest, notes, "https://github.com/coollabsio/coolify/releases/tag/x")


def image(ref, digest=None, containers=("c",)):
    repo = ref.split(":")[0]
    return {
        "image": ref,
        "image_id": "sha256:id",
        "containers": list(containers),
        "repo_digests": [f"{repo}@{digest}"] if digest else [],
    }


@pytest.fixture
def make(sessions, service, clock):
    def make(registry, coolify=None):
        check = ImageUpdatesCheck(sessions, clock, [HOST], registry, coolify, locale=EN)
        security = SecurityService(sessions, Signals(sessions, service, clock), clock, [check], locale=EN)
        return check, security

    return make


async def test_every_running_image_is_current_outdated_pinned_or_local(make, clock):
    registry = FakeRegistry({"library/postgres:18": NEW, "grafana/alloy:v1": OLD})
    check, security = make(registry)
    images = [
        image("postgres:18", OLD, ["db"]),
        image("grafana/alloy:v1", OLD, ["alloy"]),
        image("abc123:4f2e", None, ["core-1712"]),
        image(f"redis@{OLD}", OLD, ["cache"]),
    ]
    await security.ingest(report(HOST, "images", clock.now, images=images))

    await check.run(clock.now)
    lines = await security.weekly_lines(clock.now)

    assert lines[0] == f"Images ({HOST}): 1 current, 1 outdated, 1 pinned by digest, 1 built locally"
    assert lines[1] == "• newer version available: postgres:18 (db)"
    assert registry.asked == ["library/postgres:18", "grafana/alloy:v1"]
    assert overview._line_state(lines) == overview.WARN  # an outdated image needs a person


async def test_a_registry_error_is_named_and_not_counted_as_outdated(make, clock):
    check, security = make(FakeRegistry({"library/postgres:18": RegistryError("registry-1.docker.io: 429")}))
    await security.ingest(report(HOST, "images", clock.now, images=[image("postgres:18", OLD)]))

    await check.run(clock.now)
    lines = await security.weekly_lines(clock.now)

    assert "1 not checkable" in lines[0]
    assert "429" in lines[1]
    assert overview._line_state(lines) == overview.OK  # unchecked is a hint on the card, not a warning


async def test_a_missing_report_or_run_is_said_not_hidden(make, clock):
    check, security = make(FakeRegistry({}))
    assert "has never run" in (await security.weekly_lines(clock.now))[0]

    await check.run(clock.now)
    lines = await security.weekly_lines(clock.now + timedelta(days=3))
    assert "last check" in lines[0]
    assert "not checked (no report)" in lines[1]


async def test_a_newer_coolify_version_is_reported_with_its_notes(make, clock):
    check, security = make(FakeRegistry({}), FakeCoolify())

    await check.run(clock.now)
    lines = await security.weekly_lines(clock.now)

    assert ":arrow_up: Coolify v4.0.0-beta.420 → v4.0.0-beta.421 available" in lines[-3]
    assert lines[-2:] == ["• Fix proxy restart (#123)", "• New S3 backups"]


async def test_coolify_up_to_date_or_unreachable(make, clock):
    check, security = make(FakeRegistry({}), FakeCoolify(latest="v4.0.0-beta.420"))
    await check.run(clock.now)
    assert (await security.weekly_lines(clock.now))[-1] == "Coolify v4.0.0-beta.420: up to date"

    check, security = make(FakeRegistry({}), FakeCoolify(error=httpx.ConnectError("refused")))
    await check.run(clock.now)
    assert "check failed: refused" in (await security.weekly_lines(clock.now))[-1]


async def test_without_a_token_coolify_is_not_checked_and_the_report_says_so(make, clock):
    _, security = make(FakeRegistry({}))
    assert "no API token configured" in (await security.weekly_lines(clock.now))[-1]


def test_versions_and_notes():
    assert version_key("v4.0.0-beta.421") > version_key("4.0.0-beta.420")
    assert note_lines("- a\n* b\ntext\n-  ") == ["a", "b"]


async def test_the_registry_is_asked_with_an_anonymous_token_when_it_wants_one():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url}")
        if request.url.host == "auth.docker.io":
            assert request.url.params["scope"] == "repository:library/postgres:pull"
            return httpx.Response(200, json={"token": "anon"})
        if request.headers.get("authorization") != "Bearer anon":
            challenge = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/postgres:pull"'
            return httpx.Response(401, headers={"www-authenticate": challenge})
        return httpx.Response(200, headers={"docker-content-digest": NEW})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        digest = await HttpRegistry(client, EN).digest(parse_ref("postgres:18"))

    assert digest == NEW
    assert calls[0] == "HEAD https://registry-1.docker.io/v2/library/postgres/manifests/18"
    assert calls[1].startswith("GET https://auth.docker.io/token")
