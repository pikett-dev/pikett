import logging

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import create_app
from tests.fakes import ALICE, START, Clock, FakeChat, FakePager
from tests.test_api import ALERT

TOKEN = "a" * 64


def _client(database_url, **extra):
    settings = Settings(database_url=database_url, base_url="http://ops.test", oncall_people=[ALICE], **extra)
    return TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START)))


def test_without_a_token_the_webhook_stays_open_and_the_start_warns(database_url, sessions, caplog):
    with caplog.at_level(logging.WARNING, logger="app.main"), _client(database_url) as client:
        assert client.post("/api/v2/alerts", json=[ALERT]).status_code == 200
    assert sum("ALERT_TOKEN is not set" in r.message for r in caplog.records) == 1


def test_with_a_token_the_start_does_not_warn(database_url, sessions, caplog):
    with caplog.at_level(logging.WARNING, logger="app.main"), _client(database_url, alert_token=TOKEN):
        pass
    assert not any("ALERT_TOKEN" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer " + "b" * 64}, {"Authorization": TOKEN}, {"Authorization": "Basic " + TOKEN}],
)
def test_a_missing_or_wrong_token_is_a_401_and_opens_nothing(database_url, sessions, caplog, headers):
    with caplog.at_level(logging.WARNING, logger="app.api.alerts"), _client(database_url, alert_token=TOKEN) as client:
        response = client.post("/api/v2/alerts", json=[ALERT], headers=headers)
        assert response.status_code == 401
        assert client.get("/incidents/1").status_code == 404
    assert "rejected" in caplog.text
    assert "b" * 64 not in caplog.text and TOKEN not in caplog.text  # the presented value is never logged


def test_the_right_token_is_accepted(database_url, sessions):
    with _client(database_url, alert_token=TOKEN) as client:
        response = client.post("/api/v2/alerts", json=[ALERT], headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200


def test_the_token_is_checked_before_the_body(database_url, sessions):
    with _client(database_url, alert_token=TOKEN) as client:
        assert client.post("/api/v2/alerts", json={"not": "a list"}).status_code == 401


def test_an_empty_token_means_unset():
    assert Settings(alert_token="").alert_token is None


def test_a_short_token_is_refused():
    with pytest.raises(ValidationError, match="alert_token needs at least"):
        Settings(alert_token="short")  # noqa: S106


def test_the_token_must_differ_from_the_other_tokens():
    with pytest.raises(ValidationError, match="alert_token must differ"):
        Settings(alert_token=TOKEN, runner_tokens={"app-1": TOKEN})
    with pytest.raises(ValidationError, match="alert_token must differ"):
        Settings(alert_token=TOKEN, host_report_tokens={"app-1": TOKEN})


def test_the_http_client_logs_no_request_urls(database_url, sessions):
    # The heartbeat URL carries a token; httpx would write it to the log at INFO.
    loggers = [logging.getLogger("httpx"), logging.getLogger("httpcore")]
    before = [logger.level for logger in loggers]
    try:
        for logger in loggers:
            logger.setLevel(logging.INFO)  # the state a plain `logging.basicConfig(level=INFO)` leaves behind
        with _client(database_url, log_level="INFO"):
            assert all(logger.level == logging.WARNING for logger in loggers)
    finally:
        for logger, level in zip(loggers, before, strict=True):
            logger.setLevel(level)
