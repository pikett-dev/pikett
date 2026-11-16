from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.i18n import Locale
from app.notify.blocks import evidence_note
from app.security.help import all_help

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def _blank_if_none(fn: Callable[[datetime], str]) -> Callable[[datetime | None], str]:
    """A filter for a time that may be missing: nothing is shown for None."""
    return lambda moment: fn(moment) if moment else ""


def build_templates(locale: Locale, brand: str) -> Jinja2Templates:
    """The Jinja environment of one app: the language, the time zone and the brand are bound to it, so an English and
    a German app can run side by side."""
    templates = Jinja2Templates(directory=TEMPLATE_DIR)
    env = templates.env
    env.filters["confidence"] = lambda value: locale.label("common.confidence", value)
    env.filters["analysis_status"] = lambda value: locale.label("common.analysis_status", value)
    env.filters["evidence_note"] = lambda run: evidence_note(locale, run)
    env.filters["local"] = _blank_if_none(locale.date_time)
    env.filters["clock"] = _blank_if_none(locale.clock)
    env.filters["ago"] = _blank_if_none(lambda moment: locale.ago(moment, datetime.now(UTC)))
    env.filters["duration"] = lambda delta: locale.duration(delta) if delta is not None else ""
    env.filters["short_date"] = locale.day_of
    env.filters["items_of"] = lambda servers: {name: name for name in servers}
    env.globals.update(t=locale.t, label=locale.label, lang=locale.language, BRAND=brand, HELP=all_help(locale))
    return templates


def render(request: Request, name: str, context: dict[str, Any]) -> HTMLResponse:
    """Render a page with the templates of the app that serves the request."""
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(request, name, context)
