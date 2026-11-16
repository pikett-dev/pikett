"""The runner of each server as a card on the ops overview."""

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.actions.watch import SILENT_AFTER
from app.i18n import Locale
from app.models import ActionJob, RunnerHeartbeat
from app.security.overview import NEW, OK, PROBLEM, WARN, CheckRow, plain


def _ago(locale: Locale, delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    return (
        locale.t("web.runner.seconds", n=seconds) if seconds < 120 else locale.t("web.runner.minutes", n=seconds // 60)
    )


async def runner_rows(
    locale: Locale, session: AsyncSession, hosts: list[str], catalog_digest: str, now: datetime
) -> list[CheckRow]:
    """One row per server with a runner token: fresh, silent (needs you), or not seen yet.

    Unlike RunnerWatch, the silence is measured from the last poll only (not from the start of this service)."""
    beats = {beat.host: beat for beat in (await session.scalars(select(RunnerHeartbeat))).all()}
    working = set(await session.scalars(select(ActionJob.host).where(ActionJob.status.in_(("delivered", "running")))))
    last_job = {
        host: await session.scalar(
            select(ActionJob)
            .where(ActionJob.host == host, ActionJob.status != "proposed")
            .order_by(ActionJob.id.desc())
        )
        for host in hosts
    }
    rows = []
    for host in sorted(hosts):
        beat, job = beats.get(host), last_job[host]
        lines: list[str] = []
        if beat is None:
            state, lines = NEW, [locale.t("web.runner.never")]
        else:
            quiet = now - beat.last_seen_at
            if host in working:
                state, lines = OK, [locale.t("web.runner.working")]
            elif quiet > SILENT_AFTER:
                state = PROBLEM
                lines = [locale.t("web.runner.silent", ago=_ago(locale, quiet))]
            else:
                state, lines = OK, [locale.t("web.runner.ok", ago=_ago(locale, quiet))]
            if beat.catalog and beat.catalog != catalog_digest:
                state = WARN if state == OK else state
                # First: it is the headline, and the reason under "Needs you".
                lines.insert(0, locale.t("web.runner.catalog_mismatch"))
            version = beat.version or locale.t("web.runner.version_unknown")
            lines.append(locale.t("web.runner.version", version=version))
        if job is not None:
            status = locale.label("web.action_status", job.status)
            lines.append(locale.t("web.runner.last_action", runbook=job.runbook, status=status))
        rows.append(
            CheckRow(
                label=locale.t("web.runner.label", host=host),
                state=state,
                last_run=beat.last_seen_at if beat else None,
                cadence=locale.t("web.runner.cadence", poll=locale.t("web.runner.poll")),
                lines=[plain(line) for line in lines],  # the codes only decided the state above
                jobs=[],
                group="actions",
                name="RunnerHeartbeat",
            )
        )
    return rows
