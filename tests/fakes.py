import asyncio
import copy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.agent.errors import SourceError
from app.agent.llm import LlmReply, ToolCall
from app.agent.pricing import cost_usd
from app.agent.usage import LlmUsage
from app.config import Person
from app.i18n import Locale
from app.notify.base import IncidentView

# The tests run in Vienna time, like the production installation they were written for; the default of the
# settings is UTC (see tests/test_i18n.py).
TZ = ZoneInfo("Europe/Vienna")
EN = Locale("en", TZ)
DE = Locale("de", TZ)


class Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@dataclass
class FakeChat:
    posted: list[IncidentView] = field(default_factory=list)
    updates: list[IncidentView] = field(default_factory=list)
    replies: list[str] = field(default_factory=list)
    ops: list[str] = field(default_factory=list)
    messages: list[tuple[str, list[dict[str, Any]]]] = field(default_factory=list)  # (text, blocks), latest state
    fail_next_post: bool = False
    fail_reply: bool = False

    async def post_incident(self, view: IncidentView) -> tuple[str, str]:
        if self.fail_next_post:
            self.fail_next_post = False
            raise RuntimeError("slack is down")
        self.posted.append(view)
        return "C1", f"ts-{view.id}"

    async def update_incident(self, view: IncidentView, channel: str, ts: str) -> None:
        self.updates.append(view)

    async def reply(self, channel: str, ts: str, text: str) -> None:
        if self.fail_reply:
            raise RuntimeError("slack is down")
        self.replies.append(text)

    async def reply_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> str:
        if self.fail_next_post:
            self.fail_next_post = False
            raise RuntimeError("slack is down")
        self.messages.append((text, blocks))
        return f"m-{len(self.messages)}"

    async def post_ops(self, text: str) -> None:
        self.ops.append(text)

    async def post_ops_message(self, text: str, blocks: list[dict[str, Any]]) -> tuple[str, str]:
        if self.fail_next_post:
            self.fail_next_post = False
            raise RuntimeError("slack is down")
        self.messages.append((text, blocks))
        return "C_OPS", f"m-{len(self.messages)}"

    async def update_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> None:
        self.messages[int(ts.removeprefix("m-")) - 1] = (text, blocks)


@dataclass
class FakePager:
    pages: list[tuple[str, bool]] = field(default_factory=list)  # (person name, escalated)
    fail_next: bool = False
    delay: float = 0  # seconds a page takes, to let concurrent calls interleave

    async def page(self, person: Person, view: IncidentView, *, escalated: bool) -> None:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("ntfy is down")
        if self.delay:
            await asyncio.sleep(self.delay)
        self.pages.append((person.name, escalated))


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)

ALICE = Person(name="Alice", slack_user_id="U_ALICE", ntfy_topic="topic-alice")
BOB = Person(name="Bob", slack_user_id="U_BOB", ntfy_topic="topic-bob")

# Monday 2026-10-19 is rotation week 0, so Alice is on call in the week of the first tests.
START = datetime(2026, 10, 19, 10, 0, tzinfo=UTC)


def view(**overrides: object) -> IncidentView:
    args = {
        "id": 7,
        "title": "AppServerSilent",
        "severity": "P1",
        "status": "open",
        "summary": "Keine Metriken vom App-Server",
        "started_at": START,
        "resolved_at": None,
        "acked_by": None,
        "silenced_until": None,
        "url": "http://ops.test/incidents/7",
        "oncall_slack_id": "U_ALICE",
    }
    return IncidentView(**{**args, **overrides})


class FakeLogs:
    def __init__(self, rows=None, error: Exception | None = None, batches=None):
        self.rows = rows or []
        self.error = error
        self.batches = list(batches or [])  # one list of rows per call, in call order
        self.calls: list[tuple] = []

    async def query(self, query, start, end, limit):
        self.calls.append((query, start, end, limit))
        if self.error:
            raise self.error
        return self.batches.pop(0) if self.batches else self.rows


class FakeMetrics:
    def __init__(self, data=None):
        self.data = data or {"resultType": "vector", "result": []}
        self.calls: list[tuple] = []

    async def instant(self, query, at):
        self.calls.append(("instant", query, at))
        return self.data

    async def range(self, query, start, end, step_seconds):
        self.calls.append(("range", query, start, end, step_seconds))
        return self.data


class FakeTraces:
    def __init__(self, traces=None):
        self.traces = traces or []
        self.calls: list[tuple] = []

    async def services(self):
        return ["core", "admin-frontend"]

    async def search(self, service, start, end, limit, *, operation=None, tags=None, min_duration=None):
        self.calls.append((service, limit, operation, tags, min_duration))
        return self.traces

    async def get_trace(self, trace_id):
        if not self.traces:
            raise SourceError("trace not found")
        return self.traces[0]


class ScriptedLlm:
    """Plays back prepared replies and records what it was sent (messages are copied at call time)."""

    def __init__(self, replies: list[LlmReply | Exception]) -> None:
        self.replies = list(replies)
        self.calls: list[dict[str, Any]] = []

    async def complete(self, *, model, system, tools, messages, max_tokens):
        self.calls.append(
            {
                "model": model,
                "system": system,
                "tools": tools,
                "messages": copy.deepcopy(messages),
                "max_tokens": max_tokens,
            }
        )
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return replace(reply, model=model, cost_usd=cost_usd(model, reply.usage))  # as the real adapter does


def llm_reply(*calls: ToolCall, text: str = "", stop: str | None = None, usage: LlmUsage | None = None) -> LlmReply:
    raw: list[dict[str, Any]] = [{"type": "text", "text": text}] if text else []
    raw += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls]
    return LlmReply(
        tool_calls=list(calls),
        stop_reason=stop or ("tool_use" if calls else "end_turn"),
        usage=usage or LlmUsage(input_tokens=1000, output_tokens=200, cache_read_tokens=3000),
        raw=raw,
        model="",  # the scripted LLM sets model and cost when it plays the reply back, as the real adapter does
        cost_usd=0.0,
    )


class FakeLedger:
    def __init__(self, spent: float = 0.0) -> None:
        self.spent = spent
        self.charges: list[tuple[str, float]] = []

    async def spent_today(self) -> float:
        return self.spent

    async def charge(self, model: str, cost_usd: float) -> None:
        self.charges.append((model, cost_usd))
        self.spent += cost_usd
