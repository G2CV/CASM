import json

from brain.core.diff import diff_sarif, render_diff_report


def _write_sarif(path, results) -> None:
    data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "runAutomationDetails": {"id": "eng:run:http_verify"},
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_diff_sarif_added_removed(tmp_path) -> None:
    old_path = tmp_path / "old.sarif"
    new_path = tmp_path / "new.sarif"

    _write_sarif(
        old_path,
        [
            {
                "ruleId": "MISSING_CSP",
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "https://example.com/a"}}}
                ],
                "properties": {"finding_fingerprint": "fp-old", "severity": "medium"},
            }
        ],
    )
    _write_sarif(
        new_path,
        [
            {
                "ruleId": "MISSING_CSP",
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "https://example.com/a"}}}
                ],
                "properties": {"finding_fingerprint": "fp-old", "severity": "medium"},
            },
            {
                "ruleId": "MISSING_HSTS",
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "https://example.com/b"}}}
                ],
                "properties": {"finding_fingerprint": "fp-new", "severity": "high"},
            },
        ],
    )

    diff = diff_sarif(str(old_path), str(new_path))
    assert len(diff.added) == 1
    assert len(diff.removed) == 0
    assert len(diff.unchanged) == 1
    assert diff.added[0].rule_id == "MISSING_HSTS"


def test_diff_report_includes_sections(tmp_path) -> None:
    old_path = tmp_path / "old.sarif"
    new_path = tmp_path / "new.sarif"
    _write_sarif(old_path, [])
    _write_sarif(new_path, [])

    diff = diff_sarif(str(old_path), str(new_path))
    report = render_diff_report(diff, "old", "new", include_unchanged=True)
    assert "## Added" in report
    assert "## Removed" in report
    assert "## Unchanged" in report
