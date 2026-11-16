"""The message catalogs: one flat JSON file per language, dotted keys, `str.format` placeholders."""

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

LOCALES_DIR = Path(__file__).parent / "locales"
LANGUAGES = ("en", "de")
SOURCE_LANGUAGE = "en"

_strict = False
_warned: set[tuple[str, str]] = set()  # one warning per missing key, not one per use


def set_strict(value: bool) -> None:
    """Strict: a missing key raises. Tests switch it on; in production a missing key falls back to English."""
    global _strict
    _strict = value


@lru_cache
def load(language: str) -> dict[str, str]:
    data: dict[str, str] = json.loads((LOCALES_DIR / f"{language}.json").read_text(encoding="utf-8"))
    return data


def has(key: str) -> bool:
    return key in load(SOURCE_LANGUAGE)


def translate(language: str, key: str, params: dict[str, Any]) -> str:
    text = load(language).get(key)
    if text is None:
        if _strict:
            raise KeyError(f"missing message key {key!r} for language {language!r}")
        if (language, key) not in _warned:
            _warned.add((language, key))
            log.warning("missing message key %r for language %r, falling back to English", key, language)
        text = load(SOURCE_LANGUAGE).get(key)
        if text is None:
            return key
    try:
        return text.format(**params)
    except (KeyError, IndexError, ValueError):  # a catalog text with a wrong placeholder must not stop a message
        if _strict:
            raise
        log.warning("message %r for language %r does not fit its parameters", key, language)
        return key
