import logging
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.i18n import Locale, catalog

EN = Locale("en", ZoneInfo("UTC"))
DE = Locale("de", ZoneInfo("Europe/Vienna"))
MOMENT = datetime(2026, 11, 16, 13, 5, tzinfo=UTC)


def test_t_formats_placeholders():
    assert EN.t("fmt.ago.hours", n=3) == "3 h ago"
    assert DE.t("fmt.ago.hours", n=3) == "vor 3 Std."


def test_a_missing_key_raises_in_strict_mode_and_falls_back_in_production(caplog):
    with pytest.raises(KeyError, match="no.such.key"):
        EN.t("no.such.key")
    catalog.set_strict(False)
    try:
        with caplog.at_level(logging.WARNING, logger="app.i18n.catalog"):
            assert DE.t("no.such.key") == "no.such.key"
        assert "no.such.key" in caplog.text
    finally:
        catalog.set_strict(True)


def test_a_key_missing_in_one_language_falls_back_to_english(monkeypatch):
    monkeypatch.setitem(catalog.load("en"), "test.only_en", "English only")
    catalog.set_strict(False)
    try:
        assert DE.t("test.only_en") == "English only"
    finally:
        catalog.set_strict(True)


def test_label_shows_an_unknown_value_as_it_is():
    assert EN.label("fmt.weekday", "3") == "Thu"
    assert EN.label("fmt.weekday", "x") == "x"


def test_date_and_time_follow_the_language_and_the_zone():
    assert EN.date_time(MOMENT) == "2026-11-16 13:05"
    assert DE.date_time(MOMENT) == "16.11.2026 14:05"  # Vienna is UTC+1 in November
    assert EN.clock(MOMENT) == "13:05"
    assert DE.clock(MOMENT) == "14:05"
    assert EN.day(MOMENT) == "Nov 16"
    assert DE.day(MOMENT) == "16.11."


def test_relative_time():
    assert EN.ago(MOMENT, MOMENT + timedelta(seconds=30)) == "just now"
    assert EN.ago(MOMENT, MOMENT + timedelta(minutes=10)) == "10 min ago"
    assert EN.ago(MOMENT, MOMENT + timedelta(hours=3)) == "3 h ago"
    assert DE.ago(MOMENT, MOMENT + timedelta(hours=3)) == "vor 3 Std."
    assert EN.ago(MOMENT, MOMENT + timedelta(days=4)) == "4 days ago"
    assert DE.ago(MOMENT, MOMENT + timedelta(days=4)) == "vor 4 Tagen"


def test_durations_and_hours():
    assert EN.duration(timedelta(seconds=42)) == "42 s"
    assert EN.duration(timedelta(seconds=135)) == "2 min 15 s"
    assert EN.duration(timedelta(seconds=3 * 3600 + 120)) == "3 h 2 min"
    assert EN.hours(timedelta(hours=5)) == "5 h"
    assert EN.hours(timedelta(hours=72)) == "3 days"
    assert DE.hours(timedelta(hours=72)) == "3 Tage"


def test_sizes_and_decimals():
    assert EN.size(512) == "512 B"
    assert EN.size(3 * 1024) == "3.0 KB"
    assert DE.size(3 * 1024) == "3,0 KB"
    assert EN.decimal(0.5, 2) == "0.50"
    assert DE.decimal(0.5, 2) == "0,50"


def test_weekdays():
    assert [EN.weekday(i) for i in (0, 6)] == ["Mon", "Sun"]
    assert [DE.weekday(i) for i in (0, 6)] == ["Mo", "So"]


def test_settings_default_to_english_and_utc():
    settings = Settings()
    assert (settings.language, settings.timezone) == ("en", "UTC")
    assert settings.locale == Locale("en", ZoneInfo("UTC"))


def test_an_unknown_time_zone_stops_the_start_with_a_clear_message():
    with pytest.raises(ValidationError, match="unknown time zone 'Mars/Olympus'"):
        Settings(timezone="Mars/Olympus")


def test_an_unknown_language_is_refused():
    with pytest.raises(ValidationError):
        Settings(language="fr")  # type: ignore[arg-type]


def test_the_brand():
    assert Settings().brand == "Pikett"
    assert Settings(project_name="Acme").brand == "Pikett · Acme"


@pytest.mark.parametrize(("raw", "expected"), [("de_AT:de", "de"), ("en_US:en", "en"), ("DE", "de"), ("en", "en")])
def test_language_accepts_the_locale_lists_that_systems_put_in_the_environment(monkeypatch, raw, expected):
    monkeypatch.setenv("LANGUAGE", raw)

    assert Settings().language == expected


def test_a_text_that_does_not_fit_its_parameters_degrades_in_production(monkeypatch):
    monkeypatch.setitem(catalog.load("en"), "test.broken", "Hello {nme}")
    with pytest.raises(KeyError):
        EN.t("test.broken", name="x")
    catalog.set_strict(False)
    try:
        assert EN.t("test.broken", name="x") == "test.broken"
    finally:
        catalog.set_strict(True)
