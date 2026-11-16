from datetime import UTC, datetime, timedelta

import pytest

from app.agent.errors import ToolInputError
from app.agent.timewindow import parse_duration_seconds, parse_time, resolve_window

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)


def test_relative_and_absolute_times():
    assert parse_time("now", NOW) == NOW
    assert parse_time("now-30m", NOW) == NOW - timedelta(minutes=30)
    assert parse_time("now-2d", NOW) == NOW - timedelta(days=2)
    assert parse_time("2026-11-12T10:00:00Z", NOW) == datetime(2026, 11, 12, 10, 0, tzinfo=UTC)
    assert parse_time("2026-11-12T10:00:00", NOW).tzinfo == UTC


@pytest.mark.parametrize("bad", ["yesterday", "now+5m", "", 5, None])
def test_bad_times_are_rejected(bad):
    with pytest.raises(ToolInputError):
        parse_time(bad, NOW)


def test_duration_seconds():
    assert parse_duration_seconds("90s") == 90
    assert parse_duration_seconds("5m") == 300
    with pytest.raises(ToolInputError):
        parse_duration_seconds("5 minutes")


def test_window_defaults_to_the_last_hour():
    start, end = resolve_window({}, NOW, max_span=timedelta(days=1))
    assert (start, end) == (NOW - timedelta(hours=1), NOW)


def test_window_rejects_reversed_and_too_long():
    with pytest.raises(ToolInputError, match="before"):
        resolve_window({"start": "now", "end": "now-5m"}, NOW, max_span=timedelta(days=1))
    with pytest.raises(ToolInputError, match="longer"):
        resolve_window({"start": "now-2d"}, NOW, max_span=timedelta(days=1))
