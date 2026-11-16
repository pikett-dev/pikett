"""A report line that says for itself whether it needs a person.

The lines of the checks are Slack markup and go to the digest as they are. The overview page also has to know which
of them need action (a pending reboot, a newer image). A check says so when it writes the line (`Line`), so the page
does not guess from the wording. A plain `str` carries no flag; for those the overview falls back to `LEGACY_MARKERS`,
the markers of the lines as the checks wrote them before the flag existed, in both languages.
"""

LEGACY_MARKERS = (
    ":repeat:",
    "braucht Neustart von Hand",
    "needs a manual restart",
    "• neuer verfügbar",
    "• newer version available",
)


class Line(str):
    needs_action: bool

    def __new__(cls, text: str, *, needs_action: bool = False) -> "Line":
        line = super().__new__(cls, text)
        line.needs_action = needs_action
        return line


def needs_action(line: str) -> bool:
    if isinstance(line, Line):
        return line.needs_action
    return any(marker in line for marker in LEGACY_MARKERS)
