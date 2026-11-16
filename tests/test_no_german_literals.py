"""German text lives in app/i18n/locales/de.json and nowhere else in the code that ships."""

import ast
import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).parent.parent
UMLAUT = re.compile("[äöüÄÖÜß]")
# Where a German word is the point: the markers by which the overview recognises report lines that were written
# before lines carried a flag (app/security/lines.py).
ALLOWED = {"app/security/lines.py"}


def python_files() -> list[Path]:
    return sorted([*(ROOT / "app").rglob("*.py"), *(ROOT / "runner").rglob("*.py")])


def literals_with_umlauts(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    found = [
        f"{path.relative_to(ROOT)}:{node.lineno}: {node.value[:60]!r}"
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and UMLAUT.search(node.value)
    ]
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT and UMLAUT.search(token.string):
            found.append(f"{path.relative_to(ROOT)}:{token.start[0]}: comment {token.string[:60]!r}")
    return found


def test_no_python_string_or_comment_has_german_umlauts():
    found = [
        line
        for path in python_files()
        if str(path.relative_to(ROOT)) not in ALLOWED
        for line in literals_with_umlauts(path)
    ]
    assert not found, "German text belongs in app/i18n/locales/de.json:\n" + "\n".join(found)


def test_no_template_has_german_umlauts():
    found = [
        f"{path.relative_to(ROOT)}:{number}: {line.strip()[:60]}"
        for path in sorted((ROOT / "app/web/templates").glob("*.html"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if UMLAUT.search(line)
    ]
    assert not found, "German text belongs in app/i18n/locales/de.json:\n" + "\n".join(found)


def test_the_runner_catalog_keeps_german_only_in_its_language_objects():
    """runner/catalog.json carries both languages; every text is an object with an English text."""
    import json

    data = json.loads((ROOT / "runner/catalog.json").read_text(encoding="utf-8"))
    for runbook_id, runbook in data["runbooks"].items():
        for key in ("title", "description", "rollback"):
            assert isinstance(runbook[key], dict) and runbook[key].get("en"), f"{runbook_id}.{key}"
            assert not UMLAUT.search(runbook[key]["en"]), f"{runbook_id}.{key} English text"
