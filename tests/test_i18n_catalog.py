import json
from string import Formatter

import pytest

from app.i18n.catalog import LANGUAGES, LOCALES_DIR, SOURCE_LANGUAGE
from app.security.lines import LEGACY_MARKERS
from app.security.names import CHECK_KEYS, GROUPS, OTHER_GROUP

CATALOGS = {
    language: json.loads((LOCALES_DIR / f"{language}.json").read_text(encoding="utf-8")) for language in LANGUAGES
}


def placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in Formatter().parse(text) if name}


def test_every_language_has_the_same_keys():
    source = set(CATALOGS[SOURCE_LANGUAGE])
    for language, catalog in CATALOGS.items():
        assert set(catalog) == source, f"{language}: missing {source - set(catalog)}, extra {set(catalog) - source}"


@pytest.mark.parametrize("language", [lang for lang in LANGUAGES if lang != SOURCE_LANGUAGE])
def test_every_key_has_the_same_placeholders_in_every_language(language):
    source = CATALOGS[SOURCE_LANGUAGE]
    differing = {
        key: (placeholders(text), placeholders(CATALOGS[language][key]))
        for key, text in source.items()
        if placeholders(text) != placeholders(CATALOGS[language][key])
    }
    assert not differing


def test_no_text_is_empty_and_every_text_formats():
    for language, catalog in CATALOGS.items():
        for key, text in catalog.items():
            assert text.strip(), f"{language}: {key} is empty"
            text.format(**dict.fromkeys(placeholders(text), "x"))  # a stray brace would raise here


def test_the_keys_the_code_builds_from_a_value_exist():
    keys = set(CATALOGS[SOURCE_LANGUAGE])
    expected = {f"fmt.weekday.{i}" for i in range(7)}
    expected |= {f"security.{key}.label" for key in CHECK_KEYS.values()}
    expected |= {f"help.{key}.{part}" for key in CHECK_KEYS.values() for part in ("what", "why", "ours")}
    expected |= {f"web.group.{group}" for group, _ in GROUPS} | {f"web.group.{OTHER_GROUP}"}
    expected |= {f"timeline.kind.{kind}" for kind in ("job", "analysis", "incident", "action", "collector")}
    expected |= {f"web.state.{s}" for s in ("ok", "new", "warn", "overdue", "problem", "failed", "running")}
    expected |= {f"web.strip.{s}" for s in ("ok", "failed", "partial", "none")}
    expected |= {f"web.period.{p}" for p in ("24h", "7d", "30d")}
    expected |= {f"common.confidence.{c}" for c in ("low", "medium", "high")}
    expected |= {f"common.analysis_status.{s}" for s in ("running", "done", "failed")}
    expected |= {f"actions.risk.{r}" for r in ("low", "medium", "high")}
    expected |= {f"actions.verify.{v}" for v in ("pending", "ok", "red", "recovered", "skipped")}
    expected |= {f"web.verify.{v}" for v in ("pending", "ok", "red", "recovered", "skipped")}
    expected |= {
        f"web.action_status.{s}"
        for s in ("proposed", "approved", "delivered", "running", "succeeded", "failed", "rejected", "expired")
    }
    expected |= {f"actions.state.{s}" for s in ("approved", "delivered", "running", "succeeded", "rejected", "failed")}
    expected |= {f"fixpr.state.{s}" for s in ("created", "failed", "approved", "expired")}
    expected |= {f"web.fix_status.{s}" for s in ("proposed", "approved", "created")}
    expected |= {f"security.images.status.{s}" for s in ("current", "outdated", "pinned", "local", "error")}
    assert expected - keys == set()


def test_the_legacy_markers_match_the_wording_of_the_catalogs():
    """The overview falls back to these markers for report lines without a flag, so the catalogs must still say them."""
    texts = [text for catalog in CATALOGS.values() for text in catalog.values()]
    for marker in LEGACY_MARKERS:
        assert any(marker in text for text in texts), marker
