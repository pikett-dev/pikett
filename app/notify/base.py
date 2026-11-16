"""Ports for the outside world, so the incident logic runs against fakes in tests and without Slack tokens."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from app.config import Person


@dataclass(frozen=True)
class IncidentView:
    id: int
    title: str
    severity: str
    status: str
    summary: str
    started_at: datetime
    resolved_at: datetime | None
    acked_by: str | None
    silenced_until: datetime | None
    url: str
    oncall_slack_id: str | None


class ChatNotifier(Protocol):
    async def post_incident(self, view: IncidentView) -> tuple[str, str]:
        """Post the root message of a new incident and return (channel, message ts)."""
        ...

    async def update_incident(self, view: IncidentView, channel: str, ts: str) -> None:
        """Re-render the root message after an acknowledgement, silence or resolution."""
        ...

    async def reply(self, channel: str, ts: str, text: str) -> None: ...

    async def reply_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> str:
        """Reply in a thread with blocks (buttons) and return the new message's ts."""
        ...

    async def post_ops(self, text: str) -> None:
        """Post to the general ops channel (digests)."""
        ...

    async def post_ops_message(self, text: str, blocks: list[dict[str, Any]]) -> tuple[str, str]:
        """Post a message with buttons to the ops channel and return (channel, message ts)."""
        ...

    async def update_message(self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]) -> None: ...


class Pager(Protocol):
    async def page(self, person: Person, view: IncidentView, *, escalated: bool) -> None: ...
