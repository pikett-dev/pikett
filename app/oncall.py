from datetime import UTC, date, datetime, timedelta

from app.config import Person
from app.i18n import Locale


class OnCall:
    """Weekly rotation. Weeks start on Monday 00:00 in the locale's time zone; week 0 starts on the anchor Monday."""

    def __init__(self, people: list[Person], anchor: date, locale: Locale) -> None:
        if anchor.weekday() != 0:
            raise ValueError(f"oncall anchor {anchor} is not a Monday")
        self._people = people
        self._anchor = anchor
        self._locale = locale

    def _week_index(self, now: datetime) -> int:
        local = now.astimezone(self._locale.tz).date()
        monday = local - timedelta(days=local.weekday())
        return (monday - self._anchor).days // 7

    def primary(self, now: datetime) -> Person | None:
        if not self._people:
            return None
        return self._people[self._week_index(now) % len(self._people)]

    def secondary(self, now: datetime) -> Person | None:
        """The next person in the rotation; the only other person in a team of two."""
        if len(self._people) < 2:
            return None
        return self._people[(self._week_index(now) + 1) % len(self._people)]

    def describe(self, now: datetime) -> str:
        """Answer for /oncall: who is on call this week and who next week."""
        if not self._people:
            return self._locale.t("oncall.nobody")
        this_week = self.primary(now)
        next_week = self.primary(now + timedelta(days=7))
        assert this_week is not None and next_week is not None  # noqa: S101 (people is not empty)
        return self._locale.t(
            "oncall.describe",
            this_id=this_week.slack_user_id,
            this_name=this_week.name,
            next_id=next_week.slack_user_id,
            next_name=next_week.name,
        )


def utcnow() -> datetime:
    return datetime.now(UTC)
