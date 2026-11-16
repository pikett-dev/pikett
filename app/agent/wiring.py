"""The one place that builds the model chain for the analysis agent.

Everything that talks to the model gets its `Llm` from here, so the budget (and the masking in the analyst) cannot be
skipped by constructing the adapter directly. Without an API key there is no agent: the function returns None.
"""

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent.budget import Budget, DbLedger, MeteredLlm
from app.agent.llm import AnthropicLlm, Llm
from app.config import Settings


def build_agent_llm(
    settings: Settings, sessions: async_sessionmaker[AsyncSession], clock: Callable[[], datetime]
) -> tuple[Llm, Budget] | None:
    """The metered model and the budget (the incident page reads `budget.status()`), or None when the agent is off."""
    if settings.anthropic_api_key is None:
        return None
    budget = Budget.daily(
        DbLedger(sessions, clock, settings.locale.tz),
        settings.agent_model,
        settings.agent_fallback_model,
        settings.agent_daily_budget_usd,
        deep=settings.agent_deep_model,
    )
    return MeteredLlm(AnthropicLlm.from_api_key(settings.anthropic_api_key.get_secret_value()), budget), budget
