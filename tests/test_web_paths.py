import base64
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.web import templating
from app.web.templating import release_version
from tests.fakes import Clock, FakeChat, FakePager

HOST = "app-1"
KEY = Ed25519PrivateKey.generate()


def make_client(database_url: str, **settings: object) -> TestClient:
    base = {
        "database_url": database_url,
        "timezone": "Europe/Vienna",
        "runner_tokens": {HOST: "t" * 40},
        "runner_signing_key": base64.b64encode(KEY.private_bytes_raw()).decode(),
    }
    app = create_app(
        Settings(**{**base, **settings}),  # type: ignore[arg-type]
        chat=FakeChat(),
        pager=FakePager(),
        clock=Clock(datetime.now(UTC)),
    )
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def client(database_url, sessions):
    with make_client(database_url) as client:
        yield client


def test_the_new_english_paths_work(client):
    jobs = client.app.state.action_jobs
    job = client.portal.call(lambda: jobs.propose("image_prune", {}, HOST, "analysis"))

    assert client.get("/ops/history").status_code == 200
    assert client.get("/ops/history?kind=action&status=ok&host=app-1&period=30d").status_code == 200
    assert client.get("/ops/help").status_code == 200
    assert client.get(f"/ops/actions/{job.id}").status_code == 200


def test_every_old_german_path_redirects_with_301_and_the_query(client):
    cases = {
        "/ops/verlauf": "/ops/history",
        "/ops/verlauf?art=action&zeitraum=30d": "/ops/history?kind=action&period=30d",
        "/ops/verlauf?status=failed&server=app-1&art=job": "/ops/history?status=failed&host=app-1&kind=job",
        "/ops/hilfe": "/ops/help",
        "/ops/hilfe?x=1": "/ops/help?x=1",
        "/ops/aktionen/7": "/ops/actions/7",
        "/ops/aktionen/7?x=1": "/ops/actions/7?x=1",
    }
    for old, new in cases.items():
        response = client.get(old)
        assert response.status_code == 301, old
        assert response.headers["location"] == new, old


def test_a_redirected_old_link_ends_on_a_working_page(client):
    response = client.get("/ops/verlauf?art=job&zeitraum=24h", follow_redirects=True)

    assert response.status_code == 200
    assert str(response.url).endswith("/ops/history?kind=job&period=24h")


def test_an_old_action_link_with_a_bad_id_is_refused_not_redirected(client):
    assert client.get("/ops/aktionen/not-a-number").status_code == 422


def test_the_history_filters_use_the_english_parameters(client):
    page = client.get("/ops/history?kind=job&period=30d").text

    assert 'href="/ops/history?kind=job"' in page  # the chosen kind stays, the default period is dropped
    assert "art=" not in page and "zeitraum=" not in page


def test_the_favicon_and_the_icon_are_served_and_linked(client):
    favicon = client.get("/static/favicon.svg")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/svg+xml")
    icon = client.get("/static/pikett-icon.svg")
    assert icon.status_code == 200 and icon.headers["content-type"].startswith("image/svg+xml")

    page = client.get("/ops").text
    assert '<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">' in page
    assert 'src="/static/pikett-icon.svg"' in page and 'width="24"' in page


def test_the_page_language_follows_the_setting(database_url, sessions):
    with make_client(database_url) as english:
        assert '<html lang="en">' in english.get("/ops").text
    with make_client(database_url, language="de") as german:
        assert '<html lang="de">' in german.get("/ops").text


def test_the_brand_is_pikett_with_the_project_name(database_url, sessions):
    with make_client(database_url) as plain:
        assert "<title>Overview · Pikett</title>" in plain.get("/ops").text
    with make_client(database_url, project_name="Acme") as named:
        assert "<title>Overview · Pikett · Acme</title>" in named.get("/ops").text
        assert named.app.title == "Pikett · Acme"


def test_the_header_shows_the_release_next_to_the_brand(database_url, sessions):
    version = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]["version"]
    assert release_version() == version
    with make_client(database_url) as plain:
        assert f'<span class="brand-version">v{version}</span>' in plain.get("/ops").text


def test_a_release_that_cannot_be_read_is_left_out(database_url, sessions, monkeypatch, tmp_path):
    monkeypatch.setattr(templating, "PYPROJECT", tmp_path / "missing.toml")
    assert release_version() == ""
    with make_client(database_url) as plain:
        assert "brand-version" not in plain.get("/ops").text.split("</style>")[1]  # the CSS rule stays, the span goes


def test_an_old_parameter_is_dropped_when_the_new_one_is_there_too(client):
    response = client.get("/ops/verlauf?art=job&kind=action")

    assert response.headers["location"] == "/ops/history?kind=action"
