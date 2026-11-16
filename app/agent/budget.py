"""The daily spend limit of the analysis agent, enforced at the model port.

`MeteredLlm` wraps the `Llm` port, so every user of the model (the analyst now, a triage step later) is covered by the
same code and none of them carries budget logic. It is also the model selector: the caller says which model it would
like, and `Budget.pick` returns the first model, from that one down the tier table, whose daily cap is not reached yet.
With the default tiers Opus and Sonnet (the buttons) run while the day's spend is under the budget, after that only
the cheap fallback (Haiku) runs, up to a hard stop at twice the budget, and then nothing does.

A run that crosses the line in the middle moves to the fallback model for its remaining calls instead of failing.
Concurrent runs can overshoot by the calls in flight, and a call cut off by a timeout is billed by the API but never
booked here: the limit is a guard rail, not an exact cap. The day is a day in the configured time zone. Build the
chain through `app.agent.wiring.build_agent_llm`, the one place that constructs the real adapter, so the budget
cannot be skipped.
"""

import asyncio
import contextlib
import logging
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent.llm import Llm, LlmError, LlmReply
from app.agent.pricing import money
from app.db import add_spend, spent_on

log = logging.getLogger(__name__)

HARD_STOP_FACTOR = 2.0  # the fallback tier runs until the day's spend reaches this multiple of the budget


class BudgetExceeded(LlmError):
    """No model may run any more today. The analysis stops; the incident itself is not affected."""


class Ledger(Protocol):
    async def spent_today(self) -> float: ...

    async def charge(self, model: str, cost_usd: float) -> None: ...


class DbLedger:
    def __init__(self, sessions: async_sessionmaker[AsyncSession], clock: Callable[[], datetime], tz: ZoneInfo) -> None:
        self._sessions = sessions
        self._clock = clock
        self._tz = tz

    def _today(self) -> date:
        moment = self._clock()
        if moment.tzinfo is None:
            raise ValueError("the ledger needs a timezone-aware clock")
        return moment.astimezone(self._tz).date()

    async def spent_today(self) -> float:
        async with self._sessions() as session:
            return float(await spent_on(session, self._today()))

    async def charge(self, model: str, cost_usd: float) -> None:
        if not math.isfinite(cost_usd) or cost_usd < 0:
            raise ValueError(f"cannot book a cost of {cost_usd!r}")
        async with self._sessions() as session, session.begin():
            await add_spend(session, self._today(), model, money(cost_usd))


@dataclass(frozen=True)
class Tier:
    model: str
    cap_usd: float  # the model may run while the day's spend is under this


@dataclass(frozen=True)
class BudgetStatus:
    spent_usd: float
    budget_usd: float  # the cap of the first tier
    model: str | None  # the strongest model that may run now; None when nothing may run

    @property
    def exhausted(self) -> bool:
        return self.model is None


class Budget:
    def __init__(self, ledger: Ledger, tiers: Sequence[Tier]) -> None:
        self._ledger = ledger
        self._tiers = tuple(tiers)

    @classmethod
    def daily(
        cls, ledger: Ledger, primary: str, fallback: str, daily_budget_usd: float, *, deep: str | None = None
    ) -> "Budget":
        """Tiers from strong to cheap: the optional `deep` model and `primary` run under the budget, `fallback` up to
        the hard stop."""
        tiers = [Tier(model, daily_budget_usd) for model in (deep, primary) if model is not None]
        return cls(ledger, [*tiers, Tier(fallback, daily_budget_usd * HARD_STOP_FACTOR)])

    async def pick(self, preferred: str) -> str:
        """The preferred model if its cap is not reached, else the next tier down; raises when none is left."""
        models = [tier.model for tier in self._tiers]
        if preferred not in models:
            raise ValueError(f"{preferred!r} is not a budgeted model")
        try:
            spent = await self._ledger.spent_today()
        except Exception as exc:  # fail closed, with a reason the caller can show
            raise LlmError("the daily spend could not be read, so no model call was made") from exc
        for tier in self._tiers[models.index(preferred) :]:
            if spent < tier.cap_usd:
                return tier.model
        raise BudgetExceeded(f"the daily budget is used up ({spent:.2f} USD spent today)")

    async def status(self) -> BudgetStatus:
        spent = await self._ledger.spent_today()
        model = next((tier.model for tier in self._tiers if spent < tier.cap_usd), None)
        return BudgetStatus(spent, self._tiers[0].cap_usd, model)

    async def charge(self, model: str, cost_usd: float) -> None:
        await self._ledger.charge(model, cost_usd)


class MeteredLlm:
    def __init__(self, inner: Llm, budget: Budget) -> None:
        self._inner = inner
        self._budget = budget
        self._bookings: set[asyncio.Task[None]] = set()  # the event loop only holds tasks weakly: keep them alive

    async def complete(
        self, *, model: str, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]], max_tokens: int
    ) -> LlmReply:
        used = await self._budget.pick(model)
        reply = await self._inner.complete(
            model=used, system=system, tools=tools, messages=messages, max_tokens=max_tokens
        )
        booking = asyncio.ensure_future(self._budget.charge(used, reply.cost_usd))
        self._bookings.add(booking)
        booking.add_done_callback(self._booked)
        # Shielded: a timeout that cancels the run right now must not lose the booking of a call that is paid.
        # A failed booking is logged by `_booked`; the reply is good, so it is not thrown away.
        with contextlib.suppress(Exception):
            await asyncio.shield(booking)
        return reply

    def _booked(self, booking: "asyncio.Task[None]") -> None:
        self._bookings.discard(booking)
        if not booking.cancelled() and (error := booking.exception()) is not None:
            log.error("could not book a model call: %s: %s", type(error).__name__, error)
