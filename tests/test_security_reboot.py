from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models import RebootRequest
from app.notify.slack import ButtonActions
from app.security.reboot import RebootQuestions, next_window
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import EN, TZ
from tests.security_helpers import report

HOST = "app-1"
# Saturday 2026-11-14, 09:00 Vienna: daytime, so a question goes out right away.
SATURDAY = datetime(2026, 11, 14, 8, 0, tzinfo=UTC)


@pytest.fixture
def reboots(sessions, chat, clock):
    clock.now = SATURDAY
    return RebootQuestions(sessions, chat, clock, self_rebooting=["ops-server"], locale=EN)


@pytest.fixture
def buttons(reboots):
    buttons = ButtonActions(["U_ALICE"], EN)
    buttons.reboots = reboots
    return buttons


async def patches(reboots, clock, host=HOST, needed=True):
    row = await _stored(reboots, host, needed, clock.now)
    await reboots.on_patch_report(row)


async def _stored(reboots, host, needed, at):
    from app.security import hostreports

    async with reboots._sessions() as session, session.begin():
        data = {"reboot_required": needed, "reboot_packages": ["linux-image-6.8.0-49-generic"] if needed else []}
        return await hostreports.store(session, report(host, "patches", at, **data), at)


def button_value(chat) -> str:
    text, blocks = chat.messages[-1]
    return blocks[1]["elements"][0]["value"]


async def requests(sessions) -> list[RebootRequest]:
    async with sessions() as session:
        return list((await session.scalars(select(RebootRequest).order_by(RebootRequest.id))).all())


def test_the_next_window_is_the_coming_sunday_at_four():
    assert next_window(SATURDAY, TZ) == datetime(2026, 11, 15, 3, 0, tzinfo=UTC)
    assert next_window(datetime(2026, 11, 15, 2, 0, tzinfo=UTC), TZ) == datetime(2026, 11, 15, 3, 0, tzinfo=UTC)
    sunday_five = datetime(2026, 11, 15, 4, 0, tzinfo=UTC)
    assert next_window(sunday_five, TZ) == datetime(2026, 11, 22, 3, 0, tzinfo=UTC)


async def test_reboot_required_asks_in_slack_with_an_approval_button(reboots, chat, clock):
    await patches(reboots, clock)

    [(text, blocks)] = chat.messages
    assert "app-1* needs a reboot (linux-image-6.8.0-49-generic)" in text
    assert "Reboot Sunday Nov 15 04:00?" in text
    assert "valid until 09:15" in text
    assert blocks[1]["elements"][0]["action_id"] == "reboot_approve"


async def test_the_approval_records_person_and_time_and_works_once(reboots, buttons, sessions, chat, clock):
    await patches(reboots, clock)
    value = button_value(chat)
    clock.advance(timedelta(minutes=5))

    assert await buttons.handle_reboot("U_ALICE", value) is None
    assert await buttons.handle_reboot("U_ALICE", value) == "The reboot is already approved."

    [request] = await requests(sessions)
    assert (request.status, request.approved_by, request.approved_at) == ("approved", "U_ALICE", clock.now)
    assert request.scheduled_for == datetime(2026, 11, 15, 3, 0, tzinfo=UTC)
    assert "Approved by <@U_ALICE> at 09:05" in chat.messages[0][0]
    assert len(chat.messages[0][1]) == 1  # the button is gone


async def test_the_button_is_valid_for_15_minutes_only(reboots, buttons, sessions, chat, clock):
    await patches(reboots, clock)
    value = button_value(chat)
    clock.advance(timedelta(minutes=16))

    assert "has expired" in await buttons.handle_reboot("U_ALICE", value)
    assert (await requests(sessions))[0].status == "asked"

    await reboots.periodic(clock.now)
    assert (await requests(sessions))[0].status == "expired"
    assert "expired" in chat.messages[0][0]


async def test_an_expired_question_is_asked_again_with_the_next_patch_report(reboots, sessions, chat, clock):
    await patches(reboots, clock)
    clock.advance(timedelta(days=1))
    await patches(reboots, clock)

    assert [r.status for r in await requests(sessions)] == ["expired", "asked"]
    assert len(chat.messages) == 2


async def test_strangers_and_forged_values_change_nothing(reboots, buttons, sessions, chat, clock):
    await patches(reboots, clock)
    value = button_value(chat)
    request_id = value.split(":")[0]

    assert await buttons.handle_reboot("U_STRANGER", value) == "You are not allowed to do that."
    assert await buttons.handle_reboot("U_ALICE", f"{request_id}:guessed") == "Unknown approval."
    assert await buttons.handle_reboot("U_ALICE", "nonsense") == "Unknown approval."
    assert (await requests(sessions))[0].status == "asked"


async def test_without_approval_nothing_is_due(reboots, chat, clock):
    await patches(reboots, clock)

    assert await reboots.approved_reboot(HOST, clock.now + timedelta(days=2)) is None


async def test_an_approved_reboot_is_due_for_the_runner_only_from_its_time(reboots, buttons, chat, clock):
    await patches(reboots, clock)
    await buttons.handle_reboot("U_ALICE", button_value(chat))

    assert await reboots.approved_reboot(HOST, clock.now) is None
    due = await reboots.approved_reboot(HOST, datetime(2026, 11, 15, 3, 0, tzinfo=UTC))
    assert due is not None and due.approved_by == "U_ALICE"


async def test_the_question_retires_when_no_reboot_is_needed_any_more(reboots, sessions, chat, clock):
    await patches(reboots, clock)
    await patches(reboots, clock, needed=False)

    assert (await requests(sessions))[0].status == "obsolete"
    assert "No longer needed" in chat.messages[0][0]


async def test_a_self_rebooting_server_is_not_asked(reboots, chat, clock):
    await patches(reboots, clock, host="ops-server")

    assert chat.messages == []


async def test_a_question_slack_did_not_take_is_posted_by_the_next_periodic_step(reboots, sessions, chat, clock):
    chat.fail_next_post = True
    await patches(reboots, clock)
    assert chat.messages == [] and (await requests(sessions))[0].expires_at is None

    clock.advance(timedelta(minutes=30))
    await reboots.periodic(clock.now)

    [(text, _)] = chat.messages
    assert "valid until 09:45" in text  # the 15 minutes start when people can see the question


async def test_the_patch_check_hands_its_reports_to_the_questions(sessions, service, chat, clock):
    from app.security.patches import PatchCheck

    clock.now = SATURDAY
    signals = Signals(sessions, service, clock)
    patches_check = PatchCheck(sessions, signals, clock, [HOST], self_rebooting=[], locale=EN)
    reboots = RebootQuestions(sessions, chat, clock, self_rebooting=[], locale=EN)
    patches_check.on_reboot_state(reboots.on_patch_report)
    security = SecurityService(sessions, signals, clock, [patches_check, reboots], locale=EN)

    await security.ingest(report(HOST, "patches", clock.now, log="", reboot_required=True, reboot_packages=[]))

    assert len(chat.messages) == 1


async def test_a_report_at_night_waits_for_the_morning_before_it_asks(reboots, sessions, chat, clock):
    clock.now = datetime(2026, 11, 14, 2, 40, tzinfo=UTC)  # 03:40 Vienna, when the patch report arrives
    await patches(reboots, clock)
    assert chat.messages == []

    clock.now = datetime(2026, 11, 14, 6, 59, tzinfo=UTC)  # 07:59
    await reboots.periodic(clock.now)
    assert chat.messages == []

    clock.now = datetime(2026, 11, 14, 7, 0, tzinfo=UTC)  # 08:00
    await reboots.periodic(clock.now)
    [(text, _)] = chat.messages
    assert "Reboot Sunday Nov 15 04:00? Approval valid until 08:15" in text


async def test_an_approval_is_good_for_its_own_window_only(reboots, buttons, sessions, chat, clock):
    await patches(reboots, clock)
    await buttons.handle_reboot("U_ALICE", button_value(chat))
    sunday_four = datetime(2026, 11, 15, 3, 0, tzinfo=UTC)

    assert await reboots.approved_reboot(HOST, sunday_four + timedelta(hours=1)) is not None
    late = sunday_four + timedelta(hours=3)  # the runner was down; Tuesday afternoon would be worse
    assert await reboots.approved_reboot(HOST, late) is None

    await reboots.periodic(late)
    [request] = await requests(sessions)
    assert request.status == "expired"
    assert "The approved slot passed without a reboot" in chat.messages[0][0]
    assert await reboots.daily_lines(late) == []


async def test_the_approved_time_is_the_time_the_button_named(reboots, buttons, sessions, chat, clock):
    clock.now = datetime(2026, 11, 15, 2, 50, tzinfo=UTC)  # Sunday 03:50: the button says "today 04:00"
    await patches(reboots, clock)
    clock.now = datetime(2026, 11, 15, 7, 0, tzinfo=UTC)  # posted at 08:00, so it names next Sunday
    await reboots.periodic(clock.now)
    clock.advance(timedelta(minutes=5))
    await buttons.handle_reboot("U_ALICE", button_value(chat))

    [request] = await requests(sessions)
    assert request.scheduled_for == datetime(2026, 11, 22, 3, 0, tzinfo=UTC)
    assert "Sunday Nov 22 04:00" in chat.messages[0][0]
