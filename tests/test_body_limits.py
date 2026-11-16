import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.limits import ALERTS_LIMIT, API_DEFAULT_LIMIT, HOST_REPORTS_LIMIT, RUNNER_LIMIT, BodyLimit
from app.config import Settings
from app.incidents.schemas import MAX_KEY_LENGTH, MAX_LABELS_PER_ALERT, MAX_VALUE_LENGTH, AlertIn
from app.main import create_app
from tests.fakes import ALICE, START, Clock, FakeChat, FakePager
from tests.test_api import ALERT


def _echo_app(limit: int) -> TestClient:
    app = FastAPI()
    app.add_middleware(BodyLimit, limits={"/small": limit, "/prefix/": limit})

    @app.post("/small")
    @app.post("/prefix/x")
    @app.post("/free")
    async def read(request: Request) -> dict[str, int]:
        return {"bytes": len(await request.body())}

    return TestClient(app)


def test_a_body_within_the_limit_passes():
    assert _echo_app(10).post("/small", content=b"x" * 10).json() == {"bytes": 10}


def test_a_declared_length_over_the_limit_is_a_413():
    assert _echo_app(10).post("/small", content=b"x" * 11).status_code == 413


def test_a_chunked_body_without_a_length_is_stopped_while_reading():
    def chunks():
        yield b"x" * 6
        yield b"x" * 6

    response = _echo_app(10).post("/small", content=chunks())  # no Content-Length: only the stream tells
    assert response.status_code == 413


def test_a_lying_content_length_cannot_get_past_the_stream_count():
    response = _echo_app(10).post("/small", content=b"x" * 50, headers={"Content-Length": "5"})
    assert response.status_code == 413


def test_several_content_length_headers_are_all_checked():
    client = _echo_app(10)
    response = client.post("/small", content=b"x", headers=[("Content-Length", "9999"), ("Content-Length", "1")])
    assert response.status_code == 413


def test_a_prefix_limit_covers_the_paths_below_it_and_other_paths_are_free():
    client = _echo_app(10)
    assert client.post("/prefix/x", content=b"x" * 11).status_code == 413
    assert client.post("/free", content=b"x" * 5000).status_code == 200


def test_a_new_api_path_gets_the_default_limit():
    app = FastAPI()
    app.add_middleware(BodyLimit)

    @app.post("/api/v9/new")
    async def new(request: Request) -> dict[str, int]:
        return {"bytes": len(await request.body())}

    client = TestClient(app)
    assert client.post("/api/v9/new", content=b"x" * API_DEFAULT_LIMIT).status_code == 200
    assert client.post("/api/v9/new", content=b"x" * (API_DEFAULT_LIMIT + 1)).status_code == 413


def test_the_runner_limit_fits_the_largest_result():
    assert RUNNER_LIMIT > 20000 * 6  # ResultIn.summary: 20000 characters, up to 6 bytes each as JSON \\uXXXX escapes


@pytest.fixture
def client(database_url, sessions):
    settings = Settings(database_url=database_url, base_url="http://ops.test", oncall_people=[ALICE])
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        yield client


def test_the_real_routes_have_their_limits(client):
    assert client.post("/api/v2/alerts", content=b"[" + b" " * ALERTS_LIMIT + b"]").status_code == 413
    assert client.post("/api/v1/host-reports", content=b" " * (HOST_REPORTS_LIMIT + 1)).status_code == 413
    assert client.post("/api/v1/runner/poll", content=b" " * (RUNNER_LIMIT + 1)).status_code == 413
    assert client.post("/api/v2/alerts", json=[ALERT]).status_code == 200  # normal bodies are untouched


def test_a_streamed_oversize_body_on_a_real_route_is_a_413_not_a_400(client):
    def chunks():  # no Content-Length: only the stream tells how big it is
        for _ in range(ALERTS_LIMIT // 65536 + 2):
            yield b" " * 65536

    assert client.post("/api/v2/alerts", content=chunks()).status_code == 413
    assert client.post("/api/v1/runner/poll", content=b"{" + b" " * RUNNER_LIMIT).status_code == 413


def test_the_alert_count_limit(client):
    assert client.post("/api/v2/alerts", json=[ALERT] * 100).status_code == 200
    assert client.post("/api/v2/alerts", json=[ALERT] * 101).status_code == 422  # the 422 mapping, once, over HTTP


@pytest.mark.parametrize("field", ["labels", "annotations"])
def test_the_number_of_labels_and_annotations(field):
    def alert(count: int) -> AlertIn:
        return AlertIn(**{"labels": {}, field: {f"k{i}": "v" for i in range(count)}})

    alert(MAX_LABELS_PER_ALERT)
    with pytest.raises(ValidationError):
        alert(MAX_LABELS_PER_ALERT + 1)


def test_key_and_value_lengths():
    AlertIn(labels={"a" * MAX_KEY_LENGTH: "b" * MAX_VALUE_LENGTH})
    for bad in ({"a" * (MAX_KEY_LENGTH + 1): "v"}, {"k": "v" * (MAX_VALUE_LENGTH + 1)}):
        with pytest.raises(ValidationError):
            AlertIn(labels=bad)
        with pytest.raises(ValidationError):
            AlertIn(labels={"k": "v"}, annotations=bad)
