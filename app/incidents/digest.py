from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import Incident
from app.timefmt import minutes


async def build_digest(locale: Locale, sessions: async_sessionmaker[AsyncSession], now: datetime, base_url: str) -> str:
    """Daily summary for the ops channel: what is open, what was resolved in the last 24 hours."""
    since = now - timedelta(hours=24)
    async with sessions() as session:
        open_incidents = (
            await session.scalars(select(Incident).where(Incident.status == "open").order_by(Incident.started_at))
        ).all()
        resolved = (
            await session.scalars(
                select(Incident)
                .where(Incident.status == "resolved", Incident.resolved_at >= since)
                .order_by(Incident.resolved_at)
            )
        ).all()

    lines = [locale.t("digest.title")]
    if not open_incidents and not resolved:
        lines.append(locale.t("digest.none"))
        return "\n".join(lines)

    if open_incidents:
        lines.append(locale.t("digest.open_head", n=len(open_incidents)))
        for incident in open_incidents:
            link = f"<{base_url.rstrip('/')}/incidents/{incident.id}|{incident.title}>"
            lines.append(
                locale.t(
                    "digest.open_line", severity=incident.severity, link=link, n=minutes(now - incident.started_at)
                )
            )
    else:
        lines.append(locale.t("digest.nothing_open"))

    if resolved:
        lines.append(locale.t("digest.resolved_head", n=len(resolved)))
        for incident in resolved:
            duration = minutes((incident.resolved_at or now) - incident.started_at)
            lines.append(locale.t("digest.resolved_line", severity=incident.severity, title=incident.title, n=duration))
    return "\n".join(lines)
