import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent.service import AnalysisService
from app.models import ActionJob, FixPr, Incident, IncidentAnalysis, IncidentEvent
from app.web import activity
from app.web.templating import render

log = logging.getLogger(__name__)
router = APIRouter()
router.include_router(activity.router)


@router.get("/incidents", response_class=HTMLResponse)
async def incident_list(request: Request) -> HTMLResponse:
    sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions
    async with sessions() as session:
        incidents = (await session.scalars(select(Incident).order_by(Incident.started_at.desc()).limit(50))).all()
    return render(request, "incidents.html", {"incidents": incidents})


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_detail(incident_id: int, request: Request) -> HTMLResponse:
    sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions
    async with sessions() as session:
        incident = await session.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail=request.app.state.locale.t("web.error.incident_not_found"))
        events = (
            await session.scalars(
                select(IncidentEvent).where(IncidentEvent.incident_id == incident_id).order_by(IncidentEvent.at)
            )
        ).all()
        analyses = (
            await session.scalars(
                select(IncidentAnalysis)
                .where(IncidentAnalysis.incident_id == incident_id)
                .order_by(IncidentAnalysis.started_at.desc())
                .limit(5)
            )
        ).all()
        actions = (
            await session.scalars(
                select(ActionJob).where(ActionJob.incident_id == incident_id).order_by(ActionJob.created_at.desc())
            )
        ).all()
        fixes = (
            await session.scalars(select(FixPr).where(FixPr.incident_id == incident_id).order_by(FixPr.id.desc()))
        ).all()
    agent: AnalysisService | None = getattr(request.app.state, "analysis", None)
    budget = None
    if agent is not None:
        try:
            budget = await agent.budget_status()
        except Exception:  # the incident itself is more important than the budget line
            log.exception("could not read the budget for the incident page")
    context = {
        "incident": incident,
        "events": events,
        "analyses": analyses,
        "budget": budget,
        "actions": actions,
        "fixes": fixes,
    }
    return render(request, "incident.html", context)
