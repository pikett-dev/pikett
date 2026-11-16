from app.agent.fingerprints import compare_windows


def lines(template: str, n: int, start: int = 0) -> list[str]:
    return [template.format(i=start + i, ms=10 + i) for i in range(n)]


def test_similar_lines_become_one_template_and_emails_uuids_ips_are_named():
    report = compare_windows([], lines("user {i} failed to log in after {ms}ms", 20))
    assert report.templates_total == 1
    assert report.top[0].template == "user <*> failed to log in after <*>"
    assert report.top[0].window == 20
    named = [
        f"mail to user{i}@example.at from 10.0.0.{i} for 123e4567-e89b-12d3-a456-42661417{4000 + i} bounced"
        for i in range(8)
    ]
    template = compare_windows([], named).top[0].template
    assert "<EMAIL>" in template and "<IP>" in template and "<UUID>" in template
    assert "example.at" not in template


def test_new_vanished_and_common_templates_are_told_apart():
    baseline = lines("cache refresh {i} took {ms}ms", 15) + lines("health probe {i} ok", 5)
    window = lines("cache refresh {i} took {ms}ms", 10) + lines("connection pool exhausted after {ms} tries", 4)
    report = compare_windows(baseline, window)
    assert [s.template for s in report.new] == ["connection pool exhausted after <*> tries"]
    assert report.new[0].window == 4 and report.new[0].baseline == 0
    assert [s.template for s in report.vanished] == ["health probe <*> ok"]
    assert report.vanished[0].baseline == 5 and report.vanished[0].window == 0
    common = next(s for s in report.top if s.template.startswith("cache refresh"))
    assert (common.baseline, common.window) == (15, 10)
    assert report.window_lines == 14 and report.baseline_lines == 20


def test_top_is_ordered_by_window_count_and_limited():
    window = lines("alpha {i} done", 9) + lines("beta {i} done in {ms}ms with error", 3) + lines("gamma failed {i}", 6)
    report = compare_windows([], window, limit=2)
    assert [s.window for s in report.top] == sorted((s.window for s in report.top), reverse=True)
    assert len(report.top) == 2 and report.top[0].window == 9


def test_blank_lines_are_skipped_and_empty_input_is_fine():
    report = compare_windows(["", "   "], ["", "x"])
    assert report.window_lines == 1 and report.baseline_lines == 0
    empty = compare_windows([], [])
    assert empty.templates_total == 0 and empty.new == [] and empty.top == []


def test_very_long_lines_are_cut_before_mining():
    report = compare_windows([], ["boom " + "x" * 50_000])
    assert report.window_lines == 1
    assert len(report.top[0].template) <= 1100


async def test_fingerprint_window_asks_for_the_window_before_and_flags_a_cut_window():
    from datetime import UTC, datetime, timedelta

    from app.agent.fingerprints import MAX_ROWS, fingerprint_window
    from tests.fakes import FakeLogs

    start = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
    end = start + timedelta(minutes=30)
    logs = FakeLogs(batches=[[{"_msg": "old line 1"}], [{"_msg": "new line"}] * (MAX_ROWS + 1)])
    report = await fingerprint_window(logs, "*", start, end)
    assert logs.calls[0][1:3] == (start - timedelta(minutes=30), start)
    assert logs.calls[1][1:3] == (start, end)
    assert report.window_truncated is True and report.baseline_truncated is False
    assert report.as_dict()["caution"]


async def test_exactly_the_row_cap_is_not_reported_as_cut():
    from datetime import UTC, datetime, timedelta

    from app.agent.fingerprints import MAX_ROWS, fingerprint_window
    from tests.fakes import FakeLogs

    start = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
    logs = FakeLogs(batches=[[{"_msg": "a"}] * MAX_ROWS, [{"_msg": "b"}] * MAX_ROWS])
    report = await fingerprint_window(logs, "*", start, start + timedelta(minutes=5))
    assert report.window_truncated is False and report.baseline_truncated is False
    assert report.window_lines == MAX_ROWS


def test_templates_are_capped_and_no_template_goes_missing():
    long_lines = [f"boom {'word ' * 200}end{i}" for i in range(5)]
    assert all(len(s.template) <= 300 for s in compare_windows([], long_lines).top)
    many = [f"{n} {'a' * (n % 40 + 1)} k{n}x tail{n}x" for n in range(3000)]  # far more shapes than 1000
    report = compare_windows(many[:1500], many[1500:])
    assert report.baseline_lines == 1500 and report.window_lines == 1500
    assert sum(s.window for s in report.top) <= 1500 and report.templates_total >= 1


def test_a_value_cut_in_half_by_the_line_cap_does_not_survive():
    line = "x " * 499 + "anna.huber@example.at trailing"
    template = compare_windows([], [line, line]).top[0].template
    assert "anna" not in template


def test_pathological_lines_do_not_stall_the_miner():
    import time

    nasty = ["." * 1000, "a." * 500, "a-" * 500, "a+" * 500] * 50
    start = time.perf_counter()
    compare_windows(nasty, nasty)
    assert time.perf_counter() - start < 5.0
