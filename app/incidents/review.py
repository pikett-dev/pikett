"""The weekly look at the alarms: which ones fire often, end quickly and are never touched.

An alarm that fires three times a week, is gone after a few minutes and that nobody took over or acted on is a
candidate for a false alarm. The report names it and suggests what to change in the rule; whether it really is noise
stays a human decision, so nothing here changes a rule. "Touched" means taken over in Slack or with an action; an
incident somebody only read is not seen here, and a silenced one counts as untouched (silencing is a sign of noise),
so the list is a hint, not a verdict.
"""

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.incidents.memory import INTERNAL_ORIGIN
from app.incidents.service import PIPELINE_ALERT
from app.models import ActionJob, Incident
from app.notify.blocks import escape
from app.timefmt import minutes

WINDOW = timedelta(days=7)
MIN_INCIDENTS = 3  # fewer than this is not a pattern
SHORT_MEDIAN = timedelta(minutes=10)  # an alarm that ends within a few minutes on its own
MIN_FOR_MINUTES = 5  # the smallest `for:` the report suggests
MAX_LISTED = 10  # alarm names per report; the rest would only bury the candidates


@dataclass(frozen=True)
class AlarmStat:
    name: str  # the alarm and, when it has one, the host: the same alarm on two hosts is two entries
    count: int
    median: timedelta  # of the incidents that ended; zero when none did
    longest: timedelta  # of the incidents that ended
    touched: int  # incidents somebody took over or that had an action
    open: int  # still firing: such an alarm is not a false alarm yet


def _name(incident: Incident) -> str:
    name = incident.labels.get("alertname") or incident.title
    host = incident.labels.get("host")
    return f"{name} ({host})" if host else name


async def alarm_stats(sessions: async_sessionmaker[AsyncSession], now: datetime) -> list[AlarmStat]:
    """One entry per alarm that started in the last 7 days, the most frequent first."""
    async with sessions() as session:
        incidents = (
            await session.scalars(  # the alarms of vmalert only: ops-internal ones have no rule with a `for:`
                select(Incident).where(
                    Incident.started_at >= now - WINDOW,
                    Incident.title != PIPELINE_ALERT,
                    ~Incident.labels.contains(INTERNAL_ORIGIN),
                )
            )
        ).all()
        acted = set(  # only jobs a person approved: an expired proposal of the analysis is no attention
            await session.scalars(
                select(ActionJob.incident_id).where(
                    ActionJob.incident_id.in_([i.id for i in incidents]), ActionJob.approved_by.is_not(None)
                )
            )
        )
    grouped: dict[str, list[Incident]] = defaultdict(list)
    for incident in incidents:
        grouped[_name(incident)].append(incident)
    stats = []
    for name, group in grouped.items():
        seconds = [(i.resolved_at - i.started_at).total_seconds() for i in group if i.resolved_at is not None]
        stats.append(
            AlarmStat(
                name=name,
                count=len(group),
                median=timedelta(seconds=statistics.median(seconds) if seconds else 0),
                longest=timedelta(seconds=max(seconds, default=0)),
                touched=sum(i.acked_by is not None or i.id in acted for i in group),
                open=sum(i.resolved_at is None for i in group),
            )
        )
    return sorted(stats, key=lambda stat: (-stat.count, stat.name))


def candidates(stats: list[AlarmStat]) -> list[AlarmStat]:
    return [s for s in stats if s.count >= MIN_INCIDENTS and s.median < SHORT_MEDIAN and s.touched == 0 and s.open == 0]


def suggestion(locale: Locale, stat: AlarmStat) -> str:
    """What to change in the rule: wait longer than the longest blip, so these no longer page."""
    blip = min(stat.longest, SHORT_MEDIAN)  # one long run among short blips must not stretch the advice
    wait = max(MIN_FOR_MINUTES, math.ceil(blip.total_seconds() / 60) + 1)
    return locale.t("review.suggestion", n=wait)


def _median(locale: Locale, stat: AlarmStat) -> str:
    if stat.open == stat.count:
        return locale.t("review.median_open")
    return locale.t("review.median", n=minutes(stat.median))


async def review_lines(locale: Locale, sessions: async_sessionmaker[AsyncSession], now: datetime) -> list[str]:
    stats = await alarm_stats(sessions, now)
    if not stats:
        return [locale.t("review.none")]
    lines = [
        locale.t("review.line", name=escape(s.name), count=s.count, median=_median(locale, s), touched=s.touched)
        for s in stats[:MAX_LISTED]
    ]
    if len(stats) > MAX_LISTED:
        lines.append(locale.t("review.more", n=len(stats) - MAX_LISTED))
    found = candidates(stats)
    if not found:
        return [*lines, locale.t("review.no_candidates")]
    lines.append(locale.t("review.candidates_head"))
    return [
        *lines,
        *(locale.t("review.candidate_line", name=escape(s.name), text=suggestion(locale, s)) for s in found),
    ]
