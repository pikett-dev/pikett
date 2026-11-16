"""One list of what ops did and saw: job runs, agent analyses, incidents and the reports of the servers.

Each source stays in its own table; this only reads and merges them, newest first.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Row, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity.runs import SUMMARY_MAX
from app.agent.masking import Masker
from app.i18n import Locale
from app.models import ActionJob, FixPr, HostReport, Incident, IncidentAnalysis, OpsRun

OK, RUNNING, WARN, FAILED = "ok", "running", "warn", "failed"
KINDS = ("job", "analysis", "incident", "action", "collector")  # labels: `timeline.kind.<kind>`
STATUSES = (OK, RUNNING, WARN, FAILED)  # labels: `web.state.<status>`
PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
DEFAULT_PERIOD = "7d"
LIMIT = 200
SOURCE_CAP = 600  # per source, before the status filter; the collectors send about 12 reports a day (30 days: 360)
# A collector posts its kinds one after the other and Trivy comes last (up to 15 minutes); the weekly run starts 50
# minutes after the daily one, so 40 minutes keeps one run together and two runs apart.
RUN_GAP = timedelta(minutes=40)


@dataclass(frozen=True)
class Entry:
    at: datetime
    kind: str
    title: str
    status: str
    summary: str = ""
    duration: timedelta | None = None
    href: str = ""
    slack: str = ""  # link to the Slack thread of the incident, when there is one
    host: str = ""


@dataclass(frozen=True)
class Timeline:
    entries: list[Entry]
    truncated: bool  # more than LIMIT entries matched; the oldest are left out


def slack_link(channel: str | None, ts: str | None) -> str:
    """Opens the message in Slack without knowing the workspace name."""
    return f"https://slack.com/app_redirect?channel={channel}&message_ts={ts}" if channel and ts else ""


def _analysis_status(run: IncidentAnalysis) -> str:
    if run.status == "running":
        return RUNNING
    if run.status == "failed":
        return FAILED
    return OK if run.verified is not False else WARN  # unverified evidence: the page shows it, the list flags it


async def _jobs(locale: Locale, session: AsyncSession, since: datetime) -> list[Entry]:
    rows = await session.scalars(
        select(OpsRun).where(OpsRun.started_at >= since).order_by(OpsRun.started_at.desc()).limit(SOURCE_CAP)
    )
    return [
        Entry(
            at=row.started_at,
            kind="job",
            title=locale.label("timeline.job", row.name),
            status=OK if row.status == "ok" else FAILED,
            summary=row.summary,
            duration=row.finished_at - row.started_at,
            href=f"/ops/runs/{row.id}",
        )
        for row in rows
    ]


async def _analyses(locale: Locale, session: AsyncSession, since: datetime) -> list[Entry]:
    rows = await session.execute(
        select(IncidentAnalysis, Incident)
        .join(Incident, Incident.id == IncidentAnalysis.incident_id)
        .where(IncidentAnalysis.started_at >= since)
        .order_by(IncidentAnalysis.started_at.desc())
        .limit(SOURCE_CAP)
    )
    entries = []
    for run, incident in rows:
        if run.status == "done" and run.analysis:
            summary = str(run.analysis.get("summary", ""))
        else:
            summary = run.error or (locale.t("timeline.analysis_running") if run.status == "running" else "")
        entries.append(
            Entry(
                at=run.started_at,
                kind="analysis",
                title=locale.t("timeline.analysis_title", title=incident.title),
                status=_analysis_status(run),
                summary=summary,
                duration=run.finished_at - run.started_at if run.finished_at else None,
                href=f"/incidents/{incident.id}#analysis-{run.id}",
                slack=slack_link(incident.slack_channel, incident.slack_ts),
                host=incident.labels.get("host", ""),
            )
        )
    return entries


async def _incidents(locale: Locale, session: AsyncSession, since: datetime) -> list[Entry]:
    opened = await session.scalars(
        select(Incident).where(Incident.started_at >= since).order_by(Incident.started_at.desc()).limit(SOURCE_CAP)
    )
    resolved = await session.scalars(
        select(Incident).where(Incident.resolved_at >= since).order_by(Incident.resolved_at.desc()).limit(SOURCE_CAP)
    )
    entries = []
    for incident in opened:
        entries.append(
            Entry(
                at=incident.started_at,
                kind="incident",
                title=locale.t("timeline.incident_open", severity=incident.severity, title=incident.title),
                status=FAILED if incident.severity == "P1" else WARN,
                summary=incident.annotations.get("summary", ""),
                href=f"/incidents/{incident.id}",
                slack=slack_link(incident.slack_channel, incident.slack_ts),
                host=incident.labels.get("host", ""),
            )
        )
    for incident in resolved:
        assert incident.resolved_at is not None  # noqa: S101 (selected by it)
        entries.append(
            Entry(
                at=incident.resolved_at,
                kind="incident",
                title=locale.t("timeline.incident_resolved", title=incident.title),
                status=OK,
                href=f"/incidents/{incident.id}",
                slack=slack_link(incident.slack_channel, incident.slack_ts),
                host=incident.labels.get("host", ""),
            )
        )
    return entries


ACTION_STATUS = {
    "succeeded": OK,
    "failed": FAILED,
    "rejected": FAILED,
    "expired": WARN,
    "proposed": RUNNING,
    "approved": RUNNING,
    "delivered": RUNNING,
    "running": RUNNING,
}


def action_status(job: ActionJob) -> str:
    """The state of a job in the lists: an action after which the server is not healthy counts as a failure, and a
    proposal nobody approved that ran out is nothing to look at."""
    if job.verify_status == "red":
        return FAILED
    if job.status == "expired" and job.approved_by is None:
        return OK
    return ACTION_STATUS.get(job.status, WARN)


FIX_STATUS = {"created": OK, "failed": FAILED, "expired": WARN}  # anything else is still on its way


def _approved(locale: Locale, people: dict[str, str], by: str | None, at: datetime | None) -> str | None:
    if not by or not at:
        return None
    return locale.t("timeline.approved", who=people.get(by, by), at=locale.clock(at))


async def _actions(
    locale: Locale, session: AsyncSession, since: datetime, people: dict[str, str] | None = None
) -> list[Entry]:
    """Runbook jobs and fix pull requests: what was approved by whom, and how it ended."""
    names = people or {}
    mask = Masker()
    entries = []
    jobs = await session.scalars(
        select(ActionJob).where(ActionJob.created_at >= since).order_by(ActionJob.created_at.desc()).limit(SOURCE_CAP)
    )
    for job in jobs:
        status = action_status(job)
        parts = [locale.label("web.action_status", job.status)]
        if job.params:
            parts.append(", ".join(f"{k}={v}" for k, v in sorted(job.params.items())))
        if approved := _approved(locale, names, job.approved_by, job.approved_at):
            parts.append(approved)
        if job.summary:
            parts.append(mask.mask(job.summary)[:SUMMARY_MAX])
        if job.verify_status in ("ok", "red", "recovered"):
            parts.append(locale.t(f"web.verify.{job.verify_status}"))
        entries.append(
            Entry(
                at=job.created_at,
                kind="action",
                title=locale.t("timeline.action_title", runbook=job.runbook),
                status=status,
                summary=" · ".join(parts),
                duration=job.finished_at - job.started_at if job.finished_at and job.started_at else None,
                href=f"/ops/actions/{job.id}",
                host=job.host,
            )
        )
    fixes = await session.scalars(
        select(FixPr).where(FixPr.created_at >= since).order_by(FixPr.created_at.desc()).limit(SOURCE_CAP)
    )
    for fix in fixes:
        status = FIX_STATUS.get(fix.status, RUNNING)
        parts = [locale.label("web.fix_status", fix.status)]
        if approved := _approved(locale, names, fix.approved_by, fix.approved_at):
            parts.append(approved)
        if fix.error:
            parts.append(mask.mask(fix.error)[:SUMMARY_MAX])
        entries.append(
            Entry(
                at=fix.created_at,
                kind="action",
                title=locale.t("timeline.fixpr_title", repo=fix.repo, title=mask.mask(fix.title)),
                status=status,
                summary=" · ".join(parts),
                href=fix.pr_url or (f"/incidents/{fix.incident_id}" if fix.incident_id else ""),
            )
        )
    return entries


async def _collectors(locale: Locale, session: AsyncSession, since: datetime, host: str | None = None) -> list[Entry]:
    """One entry per run of a collector: a server sends its five or six reports together, so they read as one line."""
    rows = await session.execute(
        select(
            HostReport.host,
            HostReport.kind,
            HostReport.received_at,
            HostReport.data["error"].as_string().label("error"),
        )
        .where(HostReport.received_at >= since, HostReport.host == host if host else true())
        .order_by(HostReport.received_at.desc())
        .limit(SOURCE_CAP)
    )  # no payload: the reports hold whole logs
    runs: list[list[Row[Any]]] = []  # newest first; a report joins the open run of its server
    open_run: dict[str, list[Row[Any]]] = {}
    for row in rows:
        current = open_run.get(row.host)
        if (
            current and current[0].received_at - row.received_at <= RUN_GAP
        ):  # measured from the newest report: no chaining
            current.append(row)
        else:
            open_run[row.host] = [row]
            runs.append(open_run[row.host])
    entries = []
    for run in runs:
        run_host = run[0].host
        failures = [f"{row.kind}: {row.error}" for row in run if row.error]
        entries.append(
            Entry(
                at=run[0].received_at,
                kind="collector",
                title=locale.t(
                    "timeline.collector_title", host=run_host, kinds=", ".join(sorted({row.kind for row in run}))
                ),
                status=WARN if failures else OK,
                summary=Masker().mask("; ".join(failures))[:SUMMARY_MAX],  # collector errors can quote tokens or URLs
                host=run_host,
            )
        )
    return entries


async def load(
    locale: Locale,
    session: AsyncSession,
    now: datetime,
    *,
    kind: str | None = None,
    status: str | None = None,
    host: str | None = None,
    period: str = DEFAULT_PERIOD,
    limit: int = LIMIT,
    people: dict[str, str] | None = None,
) -> Timeline:
    """Newest first."""
    since = now - PERIODS.get(period, PERIODS[DEFAULT_PERIOD])
    sources = {
        "job": _jobs,
        "analysis": _analyses,
        "incident": _incidents,
        "action": _actions,
        "collector": _collectors,
    }
    wanted = [kind] if kind in sources else list(sources)
    entries: list[Entry] = []
    for name in wanted:
        if name == "collector":
            entries += await _collectors(locale, session, since, host)
        elif name == "action":
            entries += await _actions(locale, session, since, people)
        else:
            entries += await sources[name](locale, session, since)
    if status in STATUSES:
        entries = [entry for entry in entries if entry.status == status]
    if host:
        entries = [entry for entry in entries if entry.host == host]
    entries.sort(key=lambda entry: entry.at, reverse=True)
    return Timeline(entries[:limit], truncated=len(entries) > limit)


async def hosts(session: AsyncSession) -> list[str]:
    return sorted(set(await session.scalars(select(HostReport.host).distinct())))
