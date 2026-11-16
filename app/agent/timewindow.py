"""Time arguments for the agent tools: `now`, `now-30m` or an RFC 3339 timestamp, with an upper bound on the window."""

import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from app.agent.errors import ToolInputError

_RELATIVE = re.compile(r"now(?:-(\d+)([smhd]))?")
_DURATION = re.compile(r"(\d+)([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_MAX_DURATION_SECONDS = 365 * 86400


def _seconds(amount: str, unit: str) -> int:
    seconds = int(amount) * _UNIT_SECONDS[unit]
    if seconds > _MAX_DURATION_SECONDS:
        raise ToolInputError("a duration can be at most 365 days")
    return seconds


def parse_time(value: object, now: datetime) -> datetime:
    if not isinstance(value, str):
        raise ToolInputError(f"time must be a string, got {type(value).__name__}")
    text = value.strip()
    relative = _RELATIVE.fullmatch(text)
    if relative:
        amount, unit = relative.groups()
        return now if amount is None else now - timedelta(seconds=_seconds(amount, unit))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ToolInputError(f"cannot parse time {value!r}; use 'now', 'now-30m' or an RFC 3339 timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_duration_seconds(value: object) -> int:
    match = _DURATION.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise ToolInputError(f"cannot parse duration {value!r}; use values like '30s', '5m', '1h'")
    seconds = _seconds(match.group(1), match.group(2))
    if seconds < 1:
        raise ToolInputError("a duration must be at least 1 second")
    return seconds


def resolve_window(
    args: Mapping[str, Any], now: datetime, *, max_span: timedelta, default_start: str = "now-1h"
) -> tuple[datetime, datetime]:
    end = parse_time(args.get("end") or "now", now)
    start = parse_time(args.get("start") or default_start, now)
    if start >= end:
        raise ToolInputError("start must be before end")
    if end - start > max_span:
        raise ToolInputError(f"the time window is longer than the allowed {max_span}; use a shorter one")
    return start, end
