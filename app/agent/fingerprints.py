"""Log fingerprints: group log lines into templates with drain3 and compare an alarm window with the one before it.

The analysis agent cares less about single lines than about what changed: a template that appears for the first
time in the alarm window, one that vanished, and the most frequent ones. drain3 turns "user 17 failed in 12ms" and
"user 23 failed in 99ms" into one template, `user <*> failed in <*>`.

This is the only module that imports drain3 (0.9.11 from 2022). It pins old versions of jsonpickle and cachetools,
and we use none of its persistence, so dropping it later is a one-file change. The miner is in memory only and not
thread-safe: use a fresh one per call. `compare_windows` does that, so it is safe to run in a worker thread.

Limits to keep in mind: "new" means new compared with the window right before, so a template that recurs every
night looks new every time; with more than `MAX_ROWS` lines in a window only its most recent lines are mined; and
drain3 merges lines that share their length and most tokens, so `payment for order 12 accepted` and `payment for
order 13 rejected` become one template: a changed outcome word shows up as a count, not as a new template.
"""

import asyncio
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Any

from drain3.masking import MaskingInstruction
from drain3.template_miner import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from app.agent.ports import LogSource

MAX_ROWS = 2000  # log lines mined per window
_MAX_LINE_CHARS = 1000  # longer lines cost mining time and add nothing to the template
_MAX_TEMPLATE_CHARS = 300  # keeps the result small when the log lines are stack traces or JSON blobs
# Values that differ on every line but are not plain numbers (numeric tokens drain3 already generalises).
_MASKS = (
    MaskingInstruction(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "EMAIL"),  # lookbehind: no quadratic backtracking
    MaskingInstruction(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", "UUID"),
    MaskingInstruction(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP"),
    MaskingInstruction(r"\b[0-9a-fA-F]{16,}\b", "HEX"),
)


@dataclass(frozen=True)
class TemplateStat:
    template: str
    window: int  # lines matching the template in the alarm window
    baseline: int  # lines matching it in the window before


@dataclass(frozen=True)
class FingerprintReport:
    new: list[TemplateStat]
    vanished: list[TemplateStat]
    top: list[TemplateStat]
    window_lines: int
    baseline_lines: int
    templates_total: int
    window_truncated: bool = False  # the row cap cut the window: only its most recent lines were mined
    baseline_truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "lines": {"window": self.window_lines, "baseline": self.baseline_lines},
            "window_truncated": self.window_truncated,
            "baseline_truncated": self.baseline_truncated,
            "templates_total": self.templates_total,
            "new_templates": [asdict(s) for s in self.new],
            "vanished_templates": [asdict(s) for s in self.vanished],
            "top_templates": [asdict(s) for s in self.top],
        }
        if self.window_truncated or self.baseline_truncated:
            result["caution"] = (
                "a window hit the row cap, so only its most recent lines were mined; "
                "new and vanished templates can be wrong. Narrow the query or the window."
            )
        return result


def _new_miner() -> TemplateMiner:
    config = TemplateMinerConfig()  # built in code: without a config object drain3 reads drain3.ini
    config.drain_max_clusters = None  # input is capped at 2 * MAX_ROWS lines, so no eviction: nothing goes missing
    config.masking_instructions = list(_MASKS)
    return TemplateMiner(persistence_handler=None, config=config)


def _shorten(line: str) -> str:
    """Cuts at a word boundary: a value cut in half could slip past the masker that runs later."""
    if len(line) <= _MAX_LINE_CHARS:
        return line
    head = line[:_MAX_LINE_CHARS]
    return head.rsplit(" ", 1)[0] if " " in head else head


def compare_windows(baseline: Sequence[str], window: Sequence[str], *, limit: int = 15) -> FingerprintReport:
    """Mines both windows with one miner (so cluster ids match) and counts each template per window."""
    miner = _new_miner()
    before: Counter[int] = Counter()
    during: Counter[int] = Counter()
    for lines, counter in ((baseline, before), (window, during)):
        for line in lines:
            text = _shorten(line.strip())
            if text:
                counter[int(miner.add_log_message(text)["cluster_id"])] += 1

    stats = [
        TemplateStat(
            miner.drain.id_to_cluster[cluster_id].get_template()[:_MAX_TEMPLATE_CHARS],
            window=during[cluster_id],
            baseline=before[cluster_id],
        )
        for cluster_id in before.keys() | during.keys()
    ]

    by_window = sorted(stats, key=lambda s: -s.window)
    return FingerprintReport(
        new=[s for s in by_window if s.baseline == 0][:limit],
        vanished=sorted((s for s in stats if s.window == 0), key=lambda s: -s.baseline)[:limit],
        top=[s for s in by_window if s.window > 0][:limit],
        window_lines=sum(during.values()),
        baseline_lines=sum(before.values()),
        templates_total=len(stats),
    )


def _messages(rows: list[dict[str, Any]]) -> list[str]:
    return [str(row["_msg"]) for row in rows if row.get("_msg")]


def baseline_window(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    """The window of the same length right before the alarm window."""
    return start - (end - start), start


async def fingerprint_window(logs: LogSource, query: str, start: datetime, end: datetime) -> FingerprintReport:
    """Fetches the alarm window and the window right before it, and compares their templates."""
    baseline_start, baseline_end = baseline_window(start, end)
    # One row more than we mine: getting it back proves the window was cut, even if the server caps lower.
    baseline_rows, window_rows = await asyncio.gather(
        logs.query(query, baseline_start, baseline_end, MAX_ROWS + 1),
        logs.query(query, start, end, MAX_ROWS + 1),
    )
    # Mining thousands of lines takes a moment of CPU: keep it off the event loop.
    report = await asyncio.to_thread(
        compare_windows, _messages(baseline_rows[:MAX_ROWS]), _messages(window_rows[:MAX_ROWS])
    )
    return replace(
        report,
        window_truncated=len(window_rows) > MAX_ROWS,
        baseline_truncated=len(baseline_rows) > MAX_ROWS,
    )
