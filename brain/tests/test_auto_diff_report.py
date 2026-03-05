from brain.core.auto_diff_report import (
    build_auto_diff_summary,
    render_auto_diff_markdown,
    render_bootstrap_markdown,
)
from brain.core.diff import DiffFinding, DiffResult


def test_build_auto_diff_summary_counts_and_sorts() -> None:
    diff = DiffResult(
        added=[
            DiffFinding("fp1", "R_LOW", "low", "https://b.example", "low message"),
            DiffFinding("fp2", "R_HIGH", "high", "https://a.example", "high message"),
            DiffFinding("fp3", "R_HIGH_2", "high", "https://c.example", "high message 2"),
        ],
        removed=[
            DiffFinding("fp4", "R_MED", "medium", "https://d.example", "medium message"),
        ],
        unchanged=[DiffFinding("fp5", "R_INFO", "info", "https://e.example", "info message")],
    )

    summary = build_auto_diff_summary(diff, max_findings=2)

    assert summary.added_count == 3
    assert summary.removed_count == 1
    assert summary.unchanged_count == 1
    assert summary.added_by_severity == {"low": 1, "high": 2}
    assert summary.removed_by_severity == {"medium": 1}
    assert [item.rule_id for item in summary.top_added] == ["R_HIGH", "R_HIGH_2"]


def test_render_auto_diff_markdown_for_no_change() -> None:
    diff = DiffResult(added=[], removed=[], unchanged=[])
    summary = build_auto_diff_summary(diff)
    rendered = render_auto_diff_markdown(
        summary,
        old_label="old.sarif",
        new_label="new.sarif",
    )

    assert "No finding-level change detected against baseline." in rendered
    assert "Added findings: **0**" in rendered
    assert "Removed findings: **0**" in rendered


def test_render_bootstrap_markdown_marks_missing_baseline() -> None:
    rendered = render_bootstrap_markdown(
        new_label="runs/current/results.sarif",
        run_url="https://example.test/run/1",
        evidence_path="runs/current/evidence.jsonl",
    )

    assert "Baseline SARIF: _not found_" in rendered
    assert "Baseline persistence: GitHub Actions cache" in rendered
    assert "current/results.sarif" in rendered
    assert "example.test/run/1" in rendered
