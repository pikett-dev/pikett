"""Reboot question in Slack.

When the patch report says `reboot_required`, the ops channel gets "Sonntag 04:00 neu starten?" with an approval
button, posted between 08:00 and 21:00 (the report arrives at 03:40). Only allowed users may press it (checked in
ButtonActions), the button works once and for 15 minutes after the question was posted. An expired question is asked
again with the next patch report; an approval is good until two hours after its Sunday 04:00. Approving only records who
and when, and the planned time; the reboot is a runbook of the ops-runner. Without an approval nothing
happens.
"""

import hmac
import logging
import secrets
from collections.abc import Callable
from datetime import datetime, time, timedelta, tzinfo
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import HostReport, RebootRequest
from app.notify.base import ChatNotifier
from app.security.base import CheckBase

log = logging.getLogger(__name__)

ACTION_ID = "reboot_approve"
VALID_FOR = timedelta(minutes=15)
REBOOT_WEEKDAY = 6  # Sunday
REBOOT_AT = time(4, 0)
# A server in `self_rebooting_hosts` restarts itself on Sundays when /var/run/reboot-required exists: the cron job
# /etc/cron.d/ops-weekly-reboot written by deploy/ops-server/cloud-init.yaml (`0 5 * * 0`). Keep both in step.
SELF_REBOOT_AT = time(5, 0)
SELF_REBOOT_DONE_AFTER = timedelta(minutes=30)  # a report written before the reboot is judged this long after it
# The patch report arrives at 03:40; the question waits until people are awake, or nobody could press in time.
ASK_FROM, ASK_UNTIL = time(8, 0), time(21, 0)
# An approval is good for its own window only: a runner that was down must not reboot on Tuesday afternoon.
GRACE = timedelta(hours=2)
OPEN = ("asked", "approved")


def next_window(now: datetime, tz: tzinfo, at: time = REBOOT_AT) -> datetime:
    """The next Sunday `at` (default 04:00) in `tz` after `now`."""
    local = now.astimezone(tz)
    days = (REBOOT_WEEKDAY - local.weekday()) % 7
    candidate = datetime.combine(local.date() + timedelta(days=days), at, tzinfo=tz)
    return candidate if candidate > local else candidate + timedelta(days=7)


def _when(locale: Locale, moment: datetime) -> str:
    at = locale.day_time(moment)
    if moment.astimezone(locale.tz).weekday() == REBOOT_WEEKDAY:
        return locale.t("security.reboot.sunday", at=at)
    return at


def question(locale: Locale, request: RebootRequest) -> tuple[str, list[dict[str, Any]]]:
    """The Slack message for the request in its current state."""
    head = locale.t("security.reboot.head", host=request.host)
    if request.reason:
        head += f" ({request.reason})"
    if request.status == "asked":
        assert request.expires_at is not None and request.scheduled_for is not None  # noqa: S101 (posted rows)
        when = _when(locale, request.scheduled_for)
        text = locale.t("security.reboot.asked", head=head, when=when, until=locale.clock(request.expires_at))
        button = {
            "type": "button",
            "text": {"type": "plain_text", "text": locale.t("security.reboot.button", when=when)},
            "style": "primary",
            "action_id": ACTION_ID,
            "value": f"{request.id}:{request.token}",
            "confirm": {
                "title": {"type": "plain_text", "text": locale.t("security.reboot.confirm_title")},
                "text": {
                    "type": "plain_text",
                    "text": locale.t("security.reboot.confirm_text", host=request.host, when=when),
                },
                "confirm": {"type": "plain_text", "text": locale.t("slack.approve")},
                "deny": {"type": "plain_text", "text": locale.t("slack.cancel")},
            },
        }
        return text, [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "actions", "elements": [button]},
        ]
    if request.status == "approved":
        assert request.approved_at is not None and request.scheduled_for is not None  # noqa: S101
        text = locale.t(
            "security.reboot.approved",
            head=head,
            id=request.approved_by,
            at=locale.clock(request.approved_at),
            when=_when(locale, request.scheduled_for),
        )
    elif request.status == "expired" and request.approved_at is not None:
        text = locale.t("security.reboot.slot_passed", head=head)
    elif request.status == "expired":
        text = locale.t("security.reboot.expired", head=head)
    elif request.status == "obsolete":
        text = locale.t("security.reboot.obsolete", head=head)
    else:
        text = locale.t("security.reboot.done", head=head)
    return text, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]


class RebootQuestions(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        chat: ChatNotifier,
        clock: Callable[[], datetime],
        *,
        self_rebooting: list[str],
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._chat = chat
        self._clock = clock
        self._self_rebooting = set(self_rebooting)

    async def on_patch_report(self, report: HostReport) -> None:
        """Ask when the server needs a reboot; retire the question when it no longer does."""
        if report.host in self._self_rebooting:
            return
        now = self._clock()
        needed = bool(report.data.get("reboot_required"))
        reason = ", ".join(str(p) for p in report.data.get("reboot_packages") or [])[:200]
        retired: list[RebootRequest] = []  # their Slack messages are updated after the commit
        async with self._sessions() as session, session.begin():
            current = await session.scalar(
                select(RebootRequest).where(RebootRequest.host == report.host, RebootRequest.status.in_(OPEN))
            )
            if current is not None and self._expired(current, now):
                current.status = "expired"
                retired.append(current)
                await session.flush()  # frees the host for the new question (one open row per host)
                current = None
            if current is not None and not needed:
                current.status = "obsolete"
                retired.append(current)
            elif current is None and needed:
                token = secrets.token_urlsafe(16)
                session.add(
                    RebootRequest(host=report.host, reason=reason, requested_at=now, status="asked", token=token)
                )
        for request in retired:
            await self._refresh(request)
        await self.periodic(now)

    @staticmethod
    def _expired(request: RebootRequest, now: datetime) -> bool:
        if request.status == "approved":
            return request.scheduled_for is not None and now > request.scheduled_for + GRACE
        return request.expires_at is not None and now > request.expires_at

    async def _refresh(self, request: RebootRequest) -> None:
        if request.slack_channel is None or request.slack_ts is None:
            return
        text, blocks = question(self._locale, request)
        try:
            await self._chat.update_message(request.slack_channel, request.slack_ts, text, blocks)
        except Exception:
            log.exception("updating the reboot question %s failed", request.id)

    async def periodic(self, now: datetime) -> None:
        """Post waiting questions in the daytime (and again after a Slack failure); let old questions and missed
        approvals expire."""
        async with self._sessions() as session:
            rows = (await session.scalars(select(RebootRequest).where(RebootRequest.status.in_(OPEN)))).all()
        daytime = ASK_FROM <= now.astimezone(self._locale.tz).time() < ASK_UNTIL
        for request in rows:
            if request.status == "asked" and request.slack_ts is None:
                if daytime:
                    await self._post(request.id)
            elif self._expired(request, now):
                async with self._sessions() as session, session.begin():
                    row = await session.get(RebootRequest, request.id, with_for_update=True)
                    if row is None or row.status not in OPEN or not self._expired(row, now):
                        continue
                    row.status = "expired"
                await self._refresh(row)

    async def _post(self, request_id: int) -> None:
        # The row stays locked while Slack answers, so a report and the periodic step cannot both post it.
        async with self._sessions() as session, session.begin():
            request = await session.get(RebootRequest, request_id, with_for_update=True)
            if request is None or request.status != "asked" or request.slack_ts is not None:
                return
            now = self._clock()
            request.expires_at = now + VALID_FOR  # valid from the moment people can see it
            request.scheduled_for = next_window(
                now, self._locale.tz
            )  # the time the button names is the time that is approved
            text, blocks = question(self._locale, request)
            try:
                request.slack_channel, request.slack_ts = await self._chat.post_ops_message(text, blocks)
            except Exception:
                log.exception("posting the reboot question for %s failed, retrying", request.host)
                request.expires_at = request.scheduled_for = None
                return

    async def approve(self, value: str, user_id: str) -> str | None:
        """The button press of an allowed user. Returns an error text, or None when approved."""
        request_id, _, token = value.partition(":")
        if not request_id.isdigit():
            return self._locale.t("errors.approval_unknown")
        now = self._clock()
        async with self._sessions() as session, session.begin():
            request = await session.get(RebootRequest, int(request_id), with_for_update=True)
            if request is None or not hmac.compare_digest(request.token, token):
                return self._locale.t("errors.approval_unknown")
            if request.status == "approved":
                return self._locale.t("errors.reboot_approved")
            if request.status != "asked" or self._expired(request, now):
                return self._locale.t("errors.reboot_expired")
            request.status = "approved"
            request.approved_by, request.approved_at = user_id, now
        await self._refresh(request)
        return None

    async def approved_reboot(self, host: str, now: datetime) -> RebootRequest | None:
        """For the ops-runner: an approved reboot of this host that is due now (within its window)."""
        async with self._sessions() as session:
            return await session.scalar(
                select(RebootRequest).where(
                    RebootRequest.host == host,
                    RebootRequest.status == "approved",
                    RebootRequest.scheduled_for <= now,
                    RebootRequest.scheduled_for > now - GRACE,
                )
            )

    async def daily_lines(self, now: datetime) -> list[str]:
        async with self._sessions() as session:
            approved = (await session.scalars(select(RebootRequest).where(RebootRequest.status == "approved"))).all()
        lines = []
        for request in approved:
            assert request.scheduled_for is not None  # noqa: S101
            lines.append(
                self._locale.t(
                    "security.reboot.line",
                    host=request.host,
                    id=request.approved_by,
                    when=_when(self._locale, request.scheduled_for),
                )
            )
        return lines
