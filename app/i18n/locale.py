"""A language plus a time zone, and the formatting that depends on them.

Built once from the settings and passed to whatever writes text for people. Nothing reads it from a global, so a
German and an English service can run side by side.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.i18n.catalog import has, translate

_UNITS = ("B", "KB", "MB", "GB", "TB")


@dataclass(frozen=True)
class Locale:
    language: str
    tz: ZoneInfo

    def t(self, key: str, **params: Any) -> str:
        return translate(self.language, key, params)

    def label(self, prefix: str, value: str) -> str:
        """The text for an enum-like value (`<prefix>.<value>`); an unknown value is shown as it is."""
        key = f"{prefix}.{value}"
        return self.t(key) if has(key) else value

    def _local(self, moment: datetime) -> datetime:
        return moment.astimezone(self.tz)

    def date_time(self, moment: datetime) -> str:
        """en: 2026-11-16 14:05, de: 16.11.2026 14:05"""
        local = self._local(moment)
        return f"{self._date_text(local)} {local:%H:%M}"

    def full_date(self, moment: datetime) -> str:
        return self._date_text(self._local(moment))

    def _date_text(self, local: datetime) -> str:
        return f"{local:%d.%m.%Y}" if self.language == "de" else f"{local:%Y-%m-%d}"

    def day(self, moment: datetime) -> str:
        """A short date without the year: en: Nov 16, de: 16.11."""
        return self.day_of(self._local(moment).date())

    def day_of(self, day: date) -> str:
        return f"{day:%d.%m.}" if self.language == "de" else f"{day:%b} {day.day}"

    def day_time(self, moment: datetime) -> str:
        """A short date and the time: en: Nov 16 14:05, de: 16.11. 14:05"""
        local = self._local(moment)
        return f"{self.day_of(local.date())} {local:%H:%M}"

    def clock(self, moment: datetime) -> str:
        return f"{self._local(moment):%H:%M}"

    def weekday(self, index: int) -> str:
        """Short name of a weekday, 0 = Monday."""
        return self.t(f"fmt.weekday.{index}")

    def ago(self, moment: datetime, now: datetime) -> str:
        """en: 3 h ago, de: vor 3 Std."""
        seconds = int((now - moment).total_seconds())
        if seconds < 90:
            return self.t("fmt.ago.now")
        if seconds < 90 * 60:
            return self.t("fmt.ago.minutes", n=round(seconds / 60))
        if seconds < 36 * 3600:
            return self.t("fmt.ago.hours", n=round(seconds / 3600))
        return self.t("fmt.ago.days", n=round(seconds / 86400))

    def duration(self, delta: timedelta) -> str:
        seconds = round(delta.total_seconds())
        if seconds < 60:
            return f"{seconds} s"
        if seconds < 3600:
            return f"{seconds // 60} min {seconds % 60} s"
        return f"{seconds // 3600} h {seconds % 3600 // 60} min"

    def hours(self, delta: timedelta) -> str:
        """Hours, or days from 48 hours on."""
        total = int(delta.total_seconds() // 3600)
        return f"{total} h" if total < 48 else self.t("fmt.days", n=total // 24)

    def decimal(self, value: float, places: int = 1) -> str:
        text = f"{value:.{places}f}"
        return text.replace(".", ",") if self.language == "de" else text

    def size(self, n: int) -> str:
        """en: 3.0 KB, de: 3,0 KB"""
        value, unit = float(n), 0
        while value >= 1024 and unit < len(_UNITS) - 1:
            value /= 1024
            unit += 1
        text = f"{value:.0f}" if unit == 0 else self.decimal(value)
        return f"{text} {_UNITS[unit]}"
