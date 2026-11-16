"""Pure decisions about reminders, escalation and silencing. No I/O, so every branch is unit-testable."""

from datetime import datetime, timedelta

ESCALATE_AFTER = timedelta(minutes=10)

# severity -> (interval between reminders, maximum number of reminders)
_REMINDERS = {
    "P1": (timedelta(minutes=30), 6),
    "P2": (timedelta(hours=4), 3),
}


def is_silenced(silenced_until: datetime | None, now: datetime) -> bool:
    return silenced_until is not None and silenced_until > now


def should_page(severity: str) -> bool:
    return severity == "P1"


def escalation_due(
    *,
    severity: str,
    started_at: datetime,
    acked_at: datetime | None,
    escalated_at: datetime | None,
    silenced_until: datetime | None,
    now: datetime,
) -> bool:
    """An unacknowledged P1 goes to the second person after ESCALATE_AFTER."""
    if not should_page(severity) or acked_at is not None or escalated_at is not None:
        return False
    if is_silenced(silenced_until, now):
        return False
    return now - started_at >= ESCALATE_AFTER


def reminder_due(
    *,
    severity: str,
    reminder_count: int,
    last_notified_at: datetime,
    silenced_until: datetime | None,
    now: datetime,
) -> bool:
    policy = _REMINDERS.get(severity)
    if policy is None or is_silenced(silenced_until, now):
        return False
    interval, maximum = policy
    return reminder_count < maximum and now - last_notified_at >= interval
