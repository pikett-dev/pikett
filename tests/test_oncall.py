from datetime import UTC, date, datetime

import pytest

from app.oncall import OnCall
from tests.fakes import ALICE, BOB, EN


def at(year, month, day, hour=12):
    return datetime(year, month, day, hour, tzinfo=UTC)


def test_rotation_changes_every_monday():
    oncall = OnCall([ALICE, BOB], date(2026, 10, 19), EN)

    assert oncall.primary(at(2026, 10, 19)) == ALICE
    assert oncall.primary(at(2026, 10, 25)) == ALICE
    assert oncall.primary(at(2026, 10, 26)) == BOB
    assert oncall.primary(at(2026, 11, 2)) == ALICE


def test_week_starts_at_midnight_vienna_time():
    oncall = OnCall([ALICE, BOB], date(2026, 10, 19), EN)

    # Sunday 23:30 UTC is already Monday 01:30 in Vienna (CET after the clock change on 25 Oct).
    assert oncall.primary(datetime(2026, 11, 1, 23, 30, tzinfo=UTC)) == ALICE
    assert oncall.primary(datetime(2026, 10, 25, 23, 30, tzinfo=UTC)) == BOB


def test_secondary_is_the_other_person():
    oncall = OnCall([ALICE, BOB], date(2026, 10, 19), EN)

    assert oncall.secondary(at(2026, 10, 20)) == BOB
    assert oncall.secondary(at(2026, 10, 27)) == ALICE


def test_before_the_anchor_still_rotates():
    assert OnCall([ALICE, BOB], date(2026, 10, 19), EN).primary(at(2026, 10, 12)) == BOB


def test_nobody_configured():
    oncall = OnCall([], date(2026, 10, 19), EN)

    assert oncall.primary(at(2026, 10, 20)) is None
    assert oncall.secondary(at(2026, 10, 20)) is None


def test_single_person_has_no_secondary():
    assert OnCall([ALICE], date(2026, 10, 19), EN).secondary(at(2026, 10, 20)) is None


def test_anchor_must_be_a_monday():
    with pytest.raises(ValueError):
        OnCall([ALICE], date(2026, 10, 20), EN)


def test_describe_names_this_and_next_week():
    text = OnCall([ALICE, BOB], date(2026, 10, 19), EN).describe(at(2026, 10, 20))

    assert text == "This week: <@U_ALICE> (Alice). Next week: <@U_BOB> (Bob)."
    assert OnCall([], date(2026, 10, 19), EN).describe(at(2026, 10, 20)) == "Nobody is registered for on-call."
