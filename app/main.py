import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import date, datetime

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.actions.approvals import RunbookApprovals, runbook_prompt
from app.actions.fixpr import FixPullRequests, HttpBitbucket, fix_prompt
from app.actions.reboots import RebootJobs
from app.actions.service import ActionService
from app.actions.verify import ActionVerifier, HttpHealth
from app.actions.watch import RunnerWatch
from app.agent.analyst import Analyst
from app.agent.changes import HttpChanges
from app.agent.service import AnalysisService, fail_interrupted_analyses
from app.agent.tools import build_registry
from app.agent.victoria import build_sources
from app.agent.wiring import build_agent_llm
from app.api import alerts, host_reports
from app.api import runner as runner_api
from app.api.limits import BodyLimit
from app.config import Settings, get_settings
from app.db import create_engine, create_session_factory, migrate
from app.incidents.service import IncidentService
from app.jobs import Jobs
from app.models import IncidentAnalysis
from app.notify.base import ChatNotifier, Pager
from app.notify.ntfy import NtfyPager
from app.notify.slack import ButtonActions, LogNotifier, SlackNotifier
from app.oncall import OnCall, utcnow
from app.security.signals import Signals
from app.security.wiring import build_security
from app.web import legacy, pages
from app.web.templating import STATIC_DIR, build_templates
from runner.catalog import load_installed_catalog
from runner.keys import private_key_from_b64

log = logging.getLogger(__name__)

# Docker stops a container after 10 seconds by default; what is still running by then is marked interrupted at start.
SHUTDOWN_GRACE_SECONDS = 8


def create_app(
    settings: Settings | None = None,
    *,
    chat: ChatNotifier | None = None,
    pager: Pager | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> FastAPI:
    """Build the app. Chat, pager and clock can be injected; otherwise they come from the settings."""
    settings = settings or get_settings()
    locale = settings.locale

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=settings.log_level)
        if settings.alert_token is None:
            log.warning(
                "ALERT_TOKEN is not set: POST /api/v2/alerts accepts alerts from every device that can reach this "
                "service. Set ALERT_TOKEN (and the same value for vmalert) to require a bearer token."
            )
        engine = create_engine(settings.database_url)
        await migrate(engine)
        sessions = create_session_factory(engine)

        oncall = OnCall(settings.oncall_people, date.fromisoformat(settings.oncall_anchor), locale)
        # Also when the agent is off now: nothing else clears these rows.
        await fail_interrupted_analyses(sessions, clock, locale)
        agent = build_agent_llm(settings, sessions, clock)  # None without an API key: the agent is off

        async with httpx.AsyncClient(timeout=10) as client:
            catalog = load_installed_catalog(
                settings.catalog_file, required="catalog_file" in settings.model_fields_set
            )
            actions = ButtonActions(settings.slack_allowed_users, locale)
            slack: SlackNotifier | None = None
            if chat is None and settings.slack_bot_token and settings.slack_app_token:
                slack = SlackNotifier(
                    settings.slack_bot_token,
                    settings.slack_app_token,
                    settings.slack_alerts_channel,
                    settings.slack_ops_channel,
                    actions,
                    lambda: oncall.describe(clock()),
                    locale=locale,
                    with_analysis=agent is not None,
                )
            log_notifier = LogNotifier()
            active_chat: ChatNotifier = chat or slack or log_notifier
            if chat is None and slack is None:
                log.warning("Slack tokens are not set, messages are only logged")
            active_pager: Pager = pager or (
                NtfyPager(settings.ntfy_url, settings.ntfy_token, client, locale)
                if settings.oncall_people
                else log_notifier
            )

            service = IncidentService(
                sessions,
                active_chat,
                active_pager,
                oncall,
                clock,
                settings.base_url,
                locale=locale,
            )
            actions.service = service
            analysis: AnalysisService | None = None
            if agent is not None:
                llm, budget = agent
                sources = build_sources(
                    settings.victoria_logs_url, settings.victoria_metrics_url, settings.victoria_traces_url, client
                )
                if settings.coolify_url and settings.coolify_token:
                    changes = HttpChanges(
                        client, settings.coolify_url, settings.coolify_token, settings.bitbucket_read_tokens
                    )
                    sources = replace(sources, changes=changes)
                analyst = Analyst(
                    llm,
                    lambda masker: build_registry(sources, masker, clock=clock),
                    model=settings.agent_model,
                    max_iterations=settings.agent_max_iterations,
                    max_tokens=settings.agent_max_tokens,
                    timeout_seconds=settings.agent_timeout_seconds,
                    system_extra=runbook_prompt(catalog, set(settings.runner_tokens), settings.runner_applications)
                    + fix_prompt(set(settings.bitbucket_write_tokens)),
                    project_name=settings.project_name,
                    stack_description=settings.agent_stack_description,
                    language=settings.language,
                )
                analysis = AnalysisService(
                    sessions,
                    analyst,
                    budget,
                    active_chat,
                    clock,
                    settings.base_url,
                    locale=locale,
                    auto=settings.agent_auto_analyze,
                    auto_model=settings.agent_fallback_model,
                    deep_model=settings.agent_deep_model,
                    max_parallel=settings.agent_max_parallel,
                )
                actions.analysis = analysis
            app.state.analysis = analysis
            security, actions.reboots = build_security(settings, sessions, service, clock, client, active_chat)
            app.state.security = security
            app.state.host_report_tokens = {h: t.get_secret_value() for h, t in settings.host_report_tokens.items()}
            action_jobs = ActionService(
                sessions,
                clock,
                catalog,
                private_key_from_b64(settings.runner_signing_key.get_secret_value())
                if settings.runner_signing_key
                else None,
                set(settings.runner_tokens),
                settings.runner_applications,
                locale=locale,
            )
            app.state.action_jobs = action_jobs
            app.state.people = {p.slack_user_id: p.name for p in settings.oncall_people}
            app.state.runner_tokens = {h: t.get_secret_value() for h, t in settings.runner_tokens.items()}
            action_signals = Signals(sessions, service, clock)
            approvals = RunbookApprovals(sessions, action_jobs, active_chat, clock, locale=locale)
            actions.approvals = approvals
            fix_prs = FixPullRequests(
                sessions,
                HttpBitbucket(client, settings.bitbucket_write_tokens),
                active_chat,
                clock,
                set(settings.bitbucket_write_tokens),
                settings.base_url,
                locale=locale,
            )
            actions.fix_prs = fix_prs
            if analysis is not None:

                async def after_post(run: IncidentAnalysis, channel: str, ts: str) -> None:
                    for offer in (approvals.offer, fix_prs.offer):
                        try:  # one offer failing must not skip the other
                            await offer(run, channel, ts)
                        except Exception:
                            log.exception("offering a follow-up of analysis %s failed", run.id)

                analysis.on_posted = after_post
            assert actions.reboots is not None  # noqa: S101 (set by build_security above)
            action_steps = (
                ActionVerifier(
                    sessions,
                    action_jobs,
                    action_signals,
                    HttpHealth(client),
                    settings.runner_health_urls,
                    clock,
                    locale=locale,
                ),
                RebootJobs(actions.reboots, action_jobs, clock),
                approvals,
                fix_prs,
            )
            jobs = Jobs(
                service,
                active_chat,
                sessions,
                clock,
                settings.base_url,
                settings.healthchecks_ping_url,
                client,
                locale=locale,
                analysis=analysis,
                security=security,
                actions=action_jobs,
                runner_watch=RunnerWatch(sessions, action_signals, clock, set(settings.runner_tokens), locale=locale),
                action_steps=action_steps,
            )

            app.state.service = service
            app.state.sessions = sessions
            if slack:
                await slack.start()
            jobs.start()
            try:
                yield
            finally:
                await jobs.stop()  # nothing new starts from the tick ...
                if slack:
                    await slack.stop()  # ... or from a button press, so the running analyses can finish
                if analysis is not None:
                    await analysis.wait_idle(timeout=SHUTDOWN_GRACE_SECONDS)
                await engine.dispose()

    app = FastAPI(title=settings.brand, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(BodyLimit)
    app.state.alert_token = settings.alert_token.get_secret_value() if settings.alert_token else None
    app.state.locale = locale
    app.state.templates = build_templates(locale, settings.brand)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": settings.service_version}

    app.include_router(alerts.router)
    app.include_router(host_reports.router)
    app.include_router(runner_api.router)
    app.include_router(pages.router)
    app.include_router(legacy.router)
    return app
