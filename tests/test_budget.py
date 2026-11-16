import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from app.agent.analyst import Analyst, IncidentContext
from app.agent.budget import Budget, BudgetExceeded, DbLedger, MeteredLlm
from app.agent.llm import LlmError, ToolCall
from app.agent.ports import Sources
from app.agent.pricing import cost_usd
from app.agent.tools import build_registry
from app.agent.usage import LlmUsage
from app.agent.wiring import build_agent_llm
from app.config import Settings
from tests.fakes import NOW, TZ, Clock, FakeLedger, FakeLogs, FakeMetrics, FakeTraces, ScriptedLlm, llm_reply

OPUS, HAIKU = "claude-opus-5-5", "claude-haiku-5-5"


def answer(call_id="t2") -> ToolCall:
    fields = {"summary": "s", "cause": "unknown", "evidence": [], "confidence": "low", "affected": "-"}
    fields |= {
        "immediate_action": "-",
        "runbook": "",
        "runbook_host": "",
        "runbook_application": "",
        "fix_suggestion": "-",
        "risk": "-",
    }
    return ToolCall(call_id, "submit_analysis", fields)


def budget(spent=0.0) -> tuple[Budget, FakeLedger]:
    ledger = FakeLedger(spent)
    return Budget.daily(ledger, OPUS, HAIKU, daily_budget_usd=5.0), ledger


async def ask(llm, model=OPUS):
    return await llm.complete(
        model=model, system="s", tools=[], messages=[{"role": "user", "content": "x"}], max_tokens=10
    )


@pytest.mark.parametrize(("spent", "picked"), [(0, OPUS), (4.99, OPUS), (5.0, HAIKU), (9.99, HAIKU)])
async def test_the_preferred_model_runs_until_its_cap_then_the_next_tier_takes_over(spent, picked):
    assert await budget(spent)[0].pick(OPUS) == picked


async def test_the_deep_model_is_a_third_tier_above_the_primary_one():
    ledger = FakeLedger(4.0)
    tiered = Budget.daily(ledger, "claude-sonnet-5-5", HAIKU, daily_budget_usd=5.0, deep=OPUS)
    assert [await tiered.pick(m) for m in (OPUS, "claude-sonnet-5-5", HAIKU)] == [OPUS, "claude-sonnet-5-5", HAIKU]
    ledger.spent = 6.0
    assert [await tiered.pick(m) for m in (OPUS, "claude-sonnet-5-5", HAIKU)] == [HAIKU, HAIKU, HAIKU]


async def test_nothing_runs_at_the_hard_stop_and_a_cheaper_model_never_moves_up():
    with pytest.raises(BudgetExceeded, match="used up"):
        await budget(10.0)[0].pick(OPUS)
    assert await budget(0)[0].pick(HAIKU) == HAIKU  # asking for the fallback stays on the fallback
    with pytest.raises(ValueError, match="not a budgeted model"):
        await budget()[0].pick("some-new-model")


@pytest.mark.parametrize(("spent", "model", "exhausted"), [(1.0, OPUS, False), (6.0, HAIKU, False), (10.0, None, True)])
async def test_the_status_says_which_model_a_new_analysis_would_get(spent, model, exhausted):
    status = await budget(spent)[0].status()
    assert (status.model, status.exhausted, status.spent_usd, status.budget_usd) == (model, exhausted, spent, 5.0)


async def test_a_call_is_booked_at_the_cost_the_reply_reports():
    b, ledger = budget()
    usage = LlmUsage(input_tokens=1000, output_tokens=500)
    reply = await ask(MeteredLlm(ScriptedLlm([llm_reply(usage=usage)]), b))
    assert reply.cost_usd == pytest.approx(cost_usd(OPUS, usage))
    assert ledger.charges == [(OPUS, reply.cost_usd)]  # booked exactly what the reply says, priced once


async def test_over_the_budget_the_call_goes_to_the_fallback_model_and_says_so():
    inner = ScriptedLlm([llm_reply()])
    reply = await ask(MeteredLlm(inner, budget(5.0)[0]))
    assert inner.calls[0]["model"] == HAIKU and reply.model == HAIKU


async def test_nothing_is_called_once_the_hard_stop_is_reached():
    inner = ScriptedLlm([llm_reply()])
    with pytest.raises(BudgetExceeded):
        await ask(MeteredLlm(inner, budget(10.0)[0]))
    assert inner.calls == []


async def test_a_bookkeeping_error_does_not_lose_a_paid_reply(caplog):
    class BrokenLedger(FakeLedger):
        async def charge(self, model, cost_usd):
            raise RuntimeError("database down")

    b = Budget.daily(BrokenLedger(), OPUS, HAIKU, 5.0)
    with caplog.at_level("ERROR"):
        reply = await ask(MeteredLlm(ScriptedLlm([llm_reply()]), b))
    assert reply.model == OPUS and "could not book" in caplog.text


async def test_a_run_that_crosses_the_budget_midway_finishes_on_the_fallback_model():
    inner = ScriptedLlm([llm_reply(ToolCall("t1", "list_trace_services", {})), llm_reply(answer())])
    sources = Sources(FakeLogs(), FakeMetrics(), FakeTraces())
    analyst = Analyst(
        MeteredLlm(inner, budget(4.995)[0]),  # the first call is allowed; its cost pushes the day over the budget
        lambda masker: build_registry(sources, masker, clock=lambda: NOW),
        model=OPUS,
        max_iterations=5,
        max_tokens=100,
        timeout_seconds=5,
    )
    outcome = await analyst.run(IncidentContext("A", "P2", "s", NOW))
    assert [c["model"] for c in inner.calls] == [OPUS, HAIKU]  # the second call moved down instead of failing
    assert outcome.model == HAIKU and outcome.cost_usd > 0


async def test_a_run_at_the_hard_stop_ends_as_an_outcome():
    sources = Sources(FakeLogs(), FakeMetrics(), FakeTraces())
    analyst = Analyst(
        MeteredLlm(ScriptedLlm([llm_reply()]), budget(10.0)[0]),
        lambda masker: build_registry(sources, masker, clock=lambda: NOW),
        model=OPUS,
        max_iterations=5,
        max_tokens=100,
        timeout_seconds=5,
    )
    outcome = await analyst.run(IncidentContext("A", "P2", "s", NOW))
    assert outcome.analysis is None and "budget" in (outcome.error or "")


async def test_the_ledger_counts_per_vienna_day_and_across_models(sessions):
    clock = Clock(datetime(2026, 11, 12, 10, 0, tzinfo=UTC))
    ledger = DbLedger(sessions, clock, TZ)
    assert await ledger.spent_today() == 0
    await ledger.charge(OPUS, 1.25)
    await ledger.charge(OPUS, 0.5)
    await ledger.charge(HAIKU, 0.01)
    assert await ledger.spent_today() == pytest.approx(1.76)
    clock.now = datetime(2026, 11, 12, 22, 30, tzinfo=UTC)  # 23:30 in Vienna: still the same day
    assert await ledger.spent_today() == pytest.approx(1.76)
    clock.advance(timedelta(hours=1))  # 00:30 in Vienna: a new day starts with nothing spent
    assert await ledger.spent_today() == 0
    await ledger.charge(OPUS, 2.0)
    assert await ledger.spent_today() == pytest.approx(2.0)


async def test_the_ledger_needs_an_aware_clock(sessions):
    with pytest.raises(ValueError, match="timezone-aware"):
        await DbLedger(sessions, lambda: datetime(2026, 11, 12, 10, 0), TZ).spent_today()  # noqa: DTZ001


async def test_the_factory_builds_the_metered_chain_only_when_there_is_a_key(sessions):
    assert build_agent_llm(Settings(), sessions, lambda: NOW) is None
    built = build_agent_llm(Settings(anthropic_api_key=SecretStr("sk-test")), sessions, lambda: NOW)
    assert built is not None
    llm, budget_ = built
    assert isinstance(llm, MeteredLlm) and isinstance(budget_, Budget)
    assert (await budget_.status()).model == "claude-opus-5-5"  # reads the ledger of the test database


async def test_a_booking_that_is_cancelled_midway_is_still_booked():
    booked = asyncio.Event()

    class SlowLedger(FakeLedger):
        async def charge(self, model, cost_usd):
            await asyncio.sleep(0.05)  # the timeout hits while the booking is in flight
            await super().charge(model, cost_usd)
            booked.set()

    ledger = SlowLedger()
    metered = MeteredLlm(ScriptedLlm([llm_reply()]), Budget.daily(ledger, OPUS, HAIKU, 5.0))
    task = asyncio.create_task(ask(metered))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(booked.wait(), timeout=2)
    assert len(ledger.charges) == 1


async def test_a_ledger_that_cannot_be_read_stops_the_call_with_a_clear_reason():
    class BrokenLedger(FakeLedger):
        async def spent_today(self):
            raise RuntimeError("connection refused")

    inner = ScriptedLlm([llm_reply()])
    with pytest.raises(LlmError, match="could not be read"):
        await ask(MeteredLlm(inner, Budget.daily(BrokenLedger(), OPUS, HAIKU, 5.0)))
    assert inner.calls == []


@pytest.mark.parametrize("cost", [float("nan"), float("inf"), -1.0])
async def test_a_cost_that_cannot_be_booked_is_refused_by_the_ledger(sessions, cost):
    with pytest.raises(ValueError, match="cannot book"):
        await DbLedger(sessions, lambda: NOW, TZ).charge(OPUS, cost)


async def test_concurrent_bookings_add_up(sessions):
    ledger = DbLedger(sessions, lambda: NOW, TZ)
    await asyncio.gather(*(ledger.charge(OPUS, 0.1) for _ in range(20)))
    assert await ledger.spent_today() == pytest.approx(2.0)


async def test_a_run_that_moved_down_says_which_models_answered():
    inner = ScriptedLlm([llm_reply(ToolCall("t1", "list_trace_services", {})), llm_reply(answer())])
    sources = Sources(FakeLogs(), FakeMetrics(), FakeTraces())
    analyst = Analyst(
        MeteredLlm(inner, budget(4.995)[0]),
        lambda masker: build_registry(sources, masker, clock=lambda: NOW),
        model=OPUS,
        max_iterations=5,
        max_tokens=100,
        timeout_seconds=5,
    )
    outcome = await analyst.run(IncidentContext("A", "P2", "s", NOW))
    assert outcome.models == (OPUS, HAIKU) and outcome.model == HAIKU


@pytest.mark.parametrize(
    ("utc", "vienna_day"),
    [
        (datetime(2026, 3, 28, 23, 30, tzinfo=UTC), 29),  # winter time: already the next day in Vienna (UTC+1)
        (datetime(2026, 7, 1, 21, 30, tzinfo=UTC), 1),  # summer time (UTC+2): 23:30, still the same day
        (datetime(2026, 7, 1, 22, 30, tzinfo=UTC), 2),  # summer time: 00:30, the next day
    ],
)
async def test_the_day_follows_vienna_time_across_daylight_saving(sessions, utc, vienna_day):
    clock = Clock(utc)
    ledger = DbLedger(sessions, clock, TZ)
    await ledger.charge(OPUS, 1.0)
    from sqlalchemy import text

    async with sessions() as session:
        day = await session.scalar(text("SELECT day FROM agent_spend"))
    assert day.day == vienna_day
