"""What ops does and did: the overview of the checks and the history of all runs."""

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Path, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.actions.overview import runner_rows
from app.actions.service import ActionService
from app.activity import timeline
from app.agent.masking import Masker
from app.agent.service import AnalysisService
from app.i18n import Locale
from app.incidents.review import alarm_stats, candidates, suggestion
from app.models import ActionAudit, ActionJob, Incident, OpsRun
from app.security import overview as checks_overview
from app.security.names import CHECK_KEYS, GROUPS, OTHER_GROUP
from app.security.overview import CheckRow
from app.security.service import SecurityService
from app.web.templating import render

log = logging.getLogger(__name__)
router = APIRouter(prefix="/ops")

RECENT = 6
# Rows that ask for a look. "new" (not run yet) and "ok" do not.
ATTENTION = {checks_overview.PROBLEM: "problem", checks_overview.OVERDUE: "overdue", checks_overview.WARN: "warn"}


@dataclass(frozen=True)
class Attention:
    state: str  # problem, overdue or warn
    title: str
    reason: str
    href: str


def _attention(locale: Locale, rows: list[CheckRow], incidents: list[Incident]) -> list[Attention]:
    items = [
        Attention(
            "problem" if incident.severity == "P1" else "warn",
            f"{incident.severity}: {incident.title}",
            incident.annotations.get("summary", ""),
            f"/incidents/{incident.id}",
        )
        for incident in incidents
    ]
    for index, row in enumerate(rows):
        if row.state in ATTENTION:
            reason = row.headline if row.state != checks_overview.OVERDUE else locale.t("web.overview.overdue_reason")
            items.append(Attention(ATTENTION[row.state], row.label, reason, f"#check-{index}"))
    return items


def _hero(locale: Locale, items: list[Attention], total: int) -> tuple[str, str, str]:
    """The state, the sentence, and the line under it."""
    if not items:
        lead = locale.t("web.hero.lead", n=total) if total else locale.t("web.overview.no_checks")
        return "ok", locale.t("web.hero.ok"), lead
    urgent = any(item.state == "problem" for item in items)
    count = len(items)
    kind = "urgent" if urgent else "look"
    sentence = locale.t("web.hero.one_" + kind) if count == 1 else locale.t("web.hero.many_" + kind, n=count)
    return ("problem" if urgent else "warn"), sentence, locale.t("web.hero.below")


def _grouped(locale: Locale, rows: list[CheckRow]) -> list[tuple[str, list[tuple[int, CheckRow]]]]:
    """The rows under their group headings in the order of the reports; the index is the anchor of the card."""
    order = [group for group, _ in GROUPS]
    indexed = list(enumerate(rows))
    groups = [(group, [(i, row) for i, row in indexed if row.group == group]) for group in order]
    rest = [(i, row) for i, row in indexed if row.group not in order]
    return [(locale.t(f"web.group.{group}"), items) for group, items in [*groups, (OTHER_GROUP, rest)] if items]


@router.get("", response_class=HTMLResponse)
async def overview(request: Request) -> HTMLResponse:
    locale: Locale = request.app.state.locale
    sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions
    security: SecurityService | None = getattr(request.app.state, "security", None)
    agent: AnalysisService | None = getattr(request.app.state, "analysis", None)
    rows: list[CheckRow] = []
    if security is not None:
        try:
            rows = await security.overview()
        except Exception:  # the history below is still worth showing
            log.exception("could not build the check overview")
    budget = None
    if agent is not None:
        try:
            budget = await agent.budget_status()
        except Exception:
            log.exception("could not read the budget for the overview")
    now = datetime.now(UTC)
    jobs: ActionService | None = getattr(request.app.state, "action_jobs", None)
    if jobs is not None and jobs.hosts:
        try:
            async with sessions() as runner_session:  # its own session: a failing query must not break the page
                rows += await runner_rows(locale, runner_session, sorted(jobs.hosts), jobs.catalog.digest, now)
        except Exception:
            log.exception("could not build the runner cards")
            # The one check that flags a silent runner must not fail silently.
            rows.append(
                CheckRow(
                    label=locale.t("security.runner.label"),
                    state=checks_overview.WARN,
                    last_run=None,
                    cadence="",
                    lines=[locale.t("web.runner.cards_unreadable")],
                    jobs=[],
                    group="actions",
                    name="RunnerHeartbeat",
                )
            )
    review: list[tuple[str, int, str]] | None  # alarm, times in the week, what to change; None: unreadable
    try:
        stats = await alarm_stats(sessions, now)
        review = [(s.name, s.count, suggestion(locale, s)) for s in candidates(stats)]
    except Exception:
        log.exception("could not build the alarm review")
        review = None
    async with sessions() as session:
        incidents = list(
            (
                await session.scalars(
                    select(Incident)
                    .where(Incident.status == "open")
                    .order_by(Incident.severity, Incident.started_at.desc())
                )
            ).all()
        )
        recent = await timeline.load(locale, session, now, period="7d", limit=RECENT, people=_people(request))
    items = _attention(locale, rows, incidents)
    state, headline, lead = _hero(locale, items, len(rows))
    context = {
        "hero_state": state,
        "headline": headline,
        "lead": lead,
        "attention": items,
        "groups": _grouped(locale, rows),
        "budget": budget,
        "agent_on": agent is not None,
        "review": review,
        "recent": recent.entries,
        "now": now,
    }
    return render(request, "ops_overview.html", context)


def _day_label(locale: Locale, day: date, today: date) -> str:
    if day == today:
        return locale.t("web.day.today")
    if (today - day).days == 1:
        return locale.t("web.day.yesterday")
    return f"{locale.weekday(day.weekday())}, {locale.day_of(day)}"


def _by_day(locale: Locale, entries: list[timeline.Entry], now: datetime) -> list[tuple[str, list[timeline.Entry]]]:
    today = now.astimezone(locale.tz).date()
    days: list[tuple[date, list[timeline.Entry]]] = []
    for entry in entries:  # already newest first
        day = entry.at.astimezone(locale.tz).date()
        if not days or days[-1][0] != day:
            days.append((day, []))
        days[-1][1].append(entry)
    return [(_day_label(locale, day, today), items) for day, items in days]


@router.get("/history", response_class=HTMLResponse)
async def history(
    request: Request,
    kind: str = "",
    status: str = "",
    host: str = "",
    period: str = timeline.DEFAULT_PERIOD,
) -> HTMLResponse:
    locale: Locale = request.app.state.locale
    sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions
    now = datetime.now(UTC)
    async with sessions() as session:
        servers = await timeline.hosts(session)
        chosen = {
            "kind": kind if kind in timeline.KINDS else "",
            "status": status if status in timeline.STATUSES else "",
            "host": host if host in servers else "",
            "period": period if period in timeline.PERIODS else timeline.DEFAULT_PERIOD,
        }
        result = await timeline.load(
            locale,
            session,
            now,
            kind=chosen["kind"] or None,
            status=chosen["status"] or None,
            host=chosen["host"] or None,
            period=chosen["period"],
            people=_people(request),
        )

    def link(**changes: str) -> str:
        """The address of this page with some filters changed; a filter on its default value is left out."""
        query = {key: value for key, value in {**chosen, **changes}.items() if value}
        if query.get("period") == timeline.DEFAULT_PERIOD:
            del query["period"]
        return "/ops/history" + (f"?{urlencode(query)}" if query else "")

    context = {
        "days": _by_day(locale, result.entries, now),
        "count": len(result.entries),
        "truncated": result.truncated,
        "limit": timeline.LIMIT,
        "servers": servers,
        "kinds": {k: locale.t(f"timeline.kind.{k}") for k in timeline.KINDS},
        "statuses": {s: locale.t(f"web.state.{s}") for s in timeline.STATUSES},
        "periods": {p: locale.t(f"web.period.{p}") for p in timeline.PERIODS},
        "chosen": chosen,
        "link": link,
    }
    return render(request, "ops_history.html", context)


@router.get("/help", response_class=HTMLResponse)
async def help_page(request: Request) -> HTMLResponse:
    """Every check's help text in the order of the overview, so one link can explain them all."""
    locale: Locale = request.app.state.locale
    sections = [
        (
            locale.t(f"web.group.{group}"),
            [(name, locale.t(f"security.{CHECK_KEYS[name]}.label")) for name in names],
        )
        for group, names in GROUPS
    ]
    return render(request, "ops_help.html", {"sections": sections})


def _people(request: Request) -> dict[str, str]:
    """Slack user id -> name, for "approved by"."""
    return getattr(request.app.state, "people", {})


@router.get("/actions/{job_id}", response_class=HTMLResponse)
async def action_detail(request: Request, job_id: int = Path(ge=1, le=2**63 - 1)) -> HTMLResponse:
    locale: Locale = request.app.state.locale
    sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions
    async with sessions() as session:
        job = await session.get(ActionJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=locale.t("web.error.action_not_found"))
        audit = (
            await session.scalars(select(ActionAudit).where(ActionAudit.job_id == job_id).order_by(ActionAudit.id))
        ).all()
        incident = await session.get(Incident, job.incident_id) if job.incident_id else None
    jobs: ActionService | None = getattr(request.app.state, "action_jobs", None)
    book = jobs.catalog.runbooks.get(job.runbook) if jobs else None
    mask = Masker()  # the history list masks this text; the detail page must not show more
    shown = {"summary": mask.mask(job.summary), "verify_detail": mask.mask(job.verify_detail)}
    details = {entry.id: mask.mask(entry.detail) for entry in audit}
    context = {
        "job": job,
        "shown": shown,
        "details": details,
        "audit": audit,
        "incident": incident,
        "book": book,
        "book_title": book.text("title", locale.language) if book else job.runbook,
        "book_description": book.text("description", locale.language) if book else "",
        "people": _people(request),
        "status": timeline.action_status(job),
    }
    return render(request, "ops_action.html", context)


@router.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_detail(run_id: int, request: Request) -> HTMLResponse:
    locale: Locale = request.app.state.locale
    sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions
    async with sessions() as session:
        run = await session.get(OpsRun, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=locale.t("web.error.run_not_found"))
        # A failed job opens a P2 named ScheduledJobFailed for its job name (app/security/service.py).
        incident = await session.scalar(
            select(Incident)
            .where(
                Incident.labels["alertname"].astext == "ScheduledJobFailed",
                Incident.labels["job"].astext == run.name,
            )
            .order_by(Incident.started_at.desc())
        )
    title = locale.label("timeline.job", run.name)
    slack = timeline.slack_link(incident.slack_channel, incident.slack_ts) if incident else ""
    context = {"run": run, "title": title, "incident": incident, "slack": slack}
    return render(request, "ops_run.html", context)
