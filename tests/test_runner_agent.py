import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from runner import __version__
from runner.agent import MAX_JOB_BYTES, SUMMARY_LIMIT, HttpApi, Runner, SeenStore, load_config
from runner.catalog import Catalog, load_catalog
from runner.jobs import Job, format_time, sign_job
from runner.runbooks import Outcome

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
HOST = "app-1"
KEY = Ed25519PrivateKey.generate()


class FakeApi:
    def __init__(self, *envelopes: object, accept_start: bool = True) -> None:
        self.queue = [e if isinstance(e, bytes) else json.dumps(e).encode() for e in envelopes]
        self.accept_start = accept_start
        self.polls: list[tuple[str, str]] = []
        self.started_ids: list[str] = []
        self.results: list[tuple[str, str, str]] = []

    def poll(self, version: str, catalog: str) -> bytes | None:
        self.polls.append((version, catalog))
        return self.queue.pop(0) if self.queue else None

    def started(self, action_id: str) -> bool:
        self.started_ids.append(action_id)
        return self.accept_start

    def result(self, action_id: str, status: str, summary: str) -> bool:
        self.results.append((action_id, status, summary))
        return True


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog()


def signed(known: Catalog, key: Ed25519PrivateKey = KEY, **changes: Any) -> dict[str, Any]:
    payload = {
        "action_id": "act-1",
        "runbook": "image_prune",
        "params": {},
        "host": HOST,
        "issued_at": format_time(NOW),
        "expires_at": format_time(NOW + timedelta(minutes=15)),
        "catalog": known.digest,
        **changes,
    }
    return sign_job(key, payload)


def not_implemented(job: Job) -> Outcome:
    return Outcome(False, f"runbook {job.runbook.id} is not implemented on this runner")


def runner(
    api: FakeApi,
    catalog: Catalog,
    tmp_path: Path,
    execute=not_implemented,
    host: str = HOST,
) -> Runner:
    return Runner(api, KEY.public_key(), catalog, host, SeenStore(tmp_path / "seen"), execute, clock=lambda: NOW)


def recording(ran: list) -> Callable[[Job], Outcome]:
    def execute(job: Job) -> Outcome:
        ran.append(job.action_id)
        return Outcome(True, "")

    return execute


def test_no_work_means_only_a_poll_with_version_and_catalog(catalog, tmp_path) -> None:
    api = FakeApi()
    assert runner(api, catalog, tmp_path).run_once() is False
    assert api.polls == [(__version__, catalog.digest)]
    assert api.results == [] and api.started_ids == []


def test_a_valid_job_is_started_run_and_reported(catalog, tmp_path) -> None:
    api, ran = FakeApi(signed(catalog)), []

    def execute(job: Job) -> Outcome:
        ran.append(job.runbook.id)
        return Outcome(True, "3 images removed")

    assert runner(api, catalog, tmp_path, execute).run_once() is True
    assert ran == ["image_prune"]
    assert api.started_ids == ["act-1"]
    assert api.results == [("act-1", "succeeded", "3 images removed")]


def test_a_failing_runbook_is_reported_as_failed(catalog, tmp_path) -> None:
    api = FakeApi(signed(catalog))
    runner(api, catalog, tmp_path, lambda job: Outcome(False, "exit 1")).run_once()
    assert api.results == [("act-1", "failed", "exit 1")]


def test_a_crashing_runbook_does_not_stop_the_runner(catalog, tmp_path) -> None:
    def boom(job: Job) -> Outcome:
        raise RuntimeError("disk gone")

    api = FakeApi(signed(catalog))
    runner(api, catalog, tmp_path, boom).run_once()
    assert api.results == [("act-1", "failed", "RuntimeError: disk gone")]


def test_by_default_no_runbook_is_implemented_and_that_is_reported(catalog, tmp_path) -> None:
    api = FakeApi(signed(catalog))
    runner(api, catalog, tmp_path).run_once()
    assert api.results[0][1] == "failed" and "not implemented" in api.results[0][2]


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda c: {"job": signed(c)["job"], "signature": ""}, "signature"),  # unsigned
        (lambda c: signed(c, Ed25519PrivateKey.generate()), "signature"),  # wrong key
        (lambda c: signed(c, runbook="shell"), "unknown runbook"),
        (lambda c: signed(c, runbook="container_restart", params={"application": "x; id"}), "format"),
        (
            lambda c: signed(
                c, expires_at=format_time(NOW - timedelta(seconds=1)), issued_at=format_time(NOW - timedelta(minutes=5))
            ),
            "expired",
        ),
        (lambda c: signed(c, host="ops-server"), "another server"),
        (lambda c: signed(c, catalog="0" * 64), "catalog"),
    ],
)
def test_a_job_that_does_not_verify_is_rejected_reported_and_never_run(catalog, tmp_path, make, reason) -> None:
    api, ran = FakeApi(make(catalog)), []
    assert runner(api, catalog, tmp_path, recording(ran)).run_once() is True
    assert ran == [] and api.started_ids == []
    [(action_id, status, text)] = api.results
    assert (action_id, status) == ("act-1", "rejected") and reason in text


def test_a_job_that_is_not_json_or_too_big_is_dropped(catalog, tmp_path) -> None:
    for raw in (b"not json", b"x" * (MAX_JOB_BYTES + 1), b"[" * 5000):
        api = FakeApi(raw)
        assert runner(api, catalog, tmp_path).run_once() is True
        assert api.results == [] and api.started_ids == []  # no id to report it under


def test_a_job_with_a_dangerous_id_is_not_reported_under_that_id(catalog, tmp_path) -> None:
    api = FakeApi(signed(catalog, Ed25519PrivateKey.generate(), action_id="../../etc/x"))
    runner(api, catalog, tmp_path).run_once()
    assert api.results == []


def test_an_action_id_runs_once_even_after_a_restart(catalog, tmp_path) -> None:
    ran = []
    execute = recording(ran)
    first = FakeApi(signed(catalog))
    runner(first, catalog, tmp_path, execute).run_once()
    again = FakeApi(signed(catalog))  # delivered a second time, to a freshly started runner
    runner(again, catalog, tmp_path, execute).run_once()
    assert ran == ["act-1"]
    assert again.started_ids == [] and again.results == []  # a replay is dropped, not reported as a result


def test_a_job_whose_start_is_refused_is_not_run(catalog, tmp_path) -> None:
    api, ran = FakeApi(signed(catalog), accept_start=False), []
    runner(api, catalog, tmp_path, recording(ran)).run_once()
    assert ran == [] and api.results == []


def test_the_seen_store_records_before_the_job_and_prunes_old_ids(tmp_path) -> None:
    store = SeenStore(tmp_path)
    assert store.add("a-1") and not store.add("a-1")
    assert not store.add("") and not store.add("../x") and not store.add("a b")
    store.prune(NOW.timestamp() + 10 * 24 * 3600)
    assert store.add("a-1")  # forgotten after the retention, long after any job could still be valid


def test_the_config_names_the_missing_setting() -> None:
    with pytest.raises(SystemExit, match="OPS_URL"):
        load_config({})
    url, token, host, key_file, state, interval = load_config(GOOD_ENV)
    assert (url, token, host, interval) == ("http://x", "t", "h", 10.0)
    assert str(key_file).endswith("job-signing.pub") and str(state) == "/var/lib/ops-runner"


GOOD_ENV = {"OPS_URL": "http://x", "RUNNER_TOKEN": "t", "HOST_NAME": "h"}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"OPS_URL": "file:///etc/passwd"}, "http"),
        ({"OPS_URL": "http://<tailscale-ip>:8030"}, "http"),
        ({"RUNNER_TOKEN": ""}, "empty"),
        ({"POLL_SECONDS": "0"}, "between"),
        ({"POLL_SECONDS": "-5"}, "between"),
        ({"POLL_SECONDS": "120"}, "between"),
        ({"POLL_SECONDS": "nan"}, "between"),
        ({"POLL_SECONDS": "inf"}, "between"),
        ({"POLL_SECONDS": "often"}, "number"),
    ],
)
def test_a_bad_setting_stops_the_runner_with_a_clear_message(change, message) -> None:
    with pytest.raises(SystemExit, match=message):
        load_config({**GOOD_ENV, **change})


# --- the HTTP client against a small real server ------------------------------------------------------------------


@pytest.fixture
def server():
    seen: list[tuple[str, dict[str, Any], str]] = []
    answers: dict[str, tuple[int, bytes]] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
            seen.append((self.path, body, self.headers["Authorization"]))
            status, payload = answers.get(self.path, (204, b""))
            self.send_response(status)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", seen, answers
    httpd.shutdown()


def test_the_http_client_polls_starts_and_reports_with_its_token(server) -> None:
    url, seen, answers = server
    api = HttpApi(url, "secret-token")
    answers["/api/v1/runner/poll"] = (200, b'{"job": {}}')
    assert api.poll("0.1", "abc") == b'{"job": {}}'
    assert api.started("act-1") is True
    api.result("act-1", "succeeded", "x" * 10000)
    assert [p for p, _, _ in seen] == [
        "/api/v1/runner/poll",
        "/api/v1/runner/jobs/act-1/started",
        "/api/v1/runner/jobs/act-1/result",
    ]
    assert {auth for _, _, auth in seen} == {"Bearer secret-token"}
    assert seen[0][1] == {"version": "0.1", "catalog": "abc"}
    assert len(seen[2][1]["summary"]) == SUMMARY_LIMIT


def test_the_http_client_treats_204_as_no_work_and_409_as_no_start(server) -> None:
    url, _, answers = server
    api = HttpApi(url, "t")
    assert api.poll("0.1", "abc") is None
    answers["/api/v1/runner/poll"] = (401, b"")
    assert api.poll("0.1", "abc") is None
    answers["/api/v1/runner/jobs/act-1/started"] = (409, b"")
    assert api.started("act-1") is False


def test_the_http_client_survives_an_unreachable_service(monkeypatch) -> None:
    monkeypatch.setattr("runner.agent.RESULT_RETRY_SECONDS", 0)
    api = HttpApi("http://127.0.0.1:1", "t")  # nothing listens there
    assert api.poll("0.1", "abc") is None
    assert api.started("act-1") is False  # after three tries
    api.result("act-1", "succeeded", "ok")  # retries, gives up, does not raise


def test_a_start_is_retried_after_an_error_but_not_after_a_refusal(server, monkeypatch) -> None:
    monkeypatch.setattr("runner.agent.RESULT_RETRY_SECONDS", 0)
    url, seen, answers = server
    api = HttpApi(url, "t")
    answers["/api/v1/runner/jobs/a/started"] = (503, b"")
    assert api.started("a") is False and len(seen) == 3
    seen.clear()
    answers["/api/v1/runner/jobs/a/started"] = (409, b"")
    assert api.started("a") is False and len(seen) == 1


def test_a_redirect_is_not_followed_and_never_carries_the_token(server) -> None:
    url, seen, answers = server
    answers["/api/v1/runner/poll"] = (302, b"")
    assert HttpApi(url, "t").poll("0.1", "abc") is None
    assert len(seen) == 1


def test_a_result_is_retried_after_a_server_error_but_not_after_a_refusal(server, monkeypatch) -> None:
    monkeypatch.setattr("runner.agent.RESULT_RETRY_SECONDS", 0)
    url, seen, answers = server
    api = HttpApi(url, "t")
    answers["/api/v1/runner/jobs/a/result"] = (503, b"")
    api.result("a", "failed", "x")
    assert len(seen) == 5
    seen.clear()
    answers["/api/v1/runner/jobs/a/result"] = (409, b"")
    api.result("a", "failed", "x")
    assert len(seen) == 1
