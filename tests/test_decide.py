from datetime import UTC, datetime, timedelta

import pytest

from app.incidents import decide

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def escalation(**overrides):
    args = {
        "severity": "P1",
        "started_at": NOW - timedelta(minutes=11),
        "acked_at": None,
        "escalated_at": None,
        "silenced_until": None,
        "now": NOW,
    }
    return decide.escalation_due(**{**args, **overrides})


def reminder(**overrides):
    args = {
        "severity": "P2",
        "reminder_count": 0,
        "last_notified_at": NOW - timedelta(hours=5),
        "silenced_until": None,
        "now": NOW,
    }
    return decide.reminder_due(**{**args, **overrides})


def test_unacked_p1_escalates_after_ten_minutes():
    assert escalation()
    assert not escalation(started_at=NOW - timedelta(minutes=9))


@pytest.mark.parametrize(
    "overrides",
    [
        {"severity": "P2"},
        {"acked_at": NOW},
        {"escalated_at": NOW},
        {"silenced_until": NOW + timedelta(hours=1)},
    ],
)
def test_no_escalation_when(overrides):
    assert not escalation(**overrides)


def test_expired_silence_does_not_block_escalation():
    assert escalation(silenced_until=NOW - timedelta(minutes=1))


def test_p2_reminder_every_four_hours_up_to_three_times():
    assert reminder()
    assert not reminder(last_notified_at=NOW - timedelta(hours=3))
    assert not reminder(reminder_count=3)


def test_p3_never_reminds_and_silence_blocks_reminders():
    assert not reminder(severity="P3")
    assert not reminder(silenced_until=NOW + timedelta(minutes=5))


def test_only_p1_pages():
    assert decide.should_page("P1")
    assert not decide.should_page("P2")
