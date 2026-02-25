import json

from brain.core.alerts import AlertOptions, dispatch_diff_alerts
from brain.core.diff import DiffFinding, DiffResult


class RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, run_summary: dict) -> None:
        self.events.append(run_summary)


def test_dispatch_diff_alerts_applies_filters_and_limits(tmp_path) -> None:
    diff = DiffResult(
        added=[
            DiffFinding("fp1", "MISSING_CSP", "medium", "https://a.example", "m1"),
            DiffFinding("fp2", "MISSING_HSTS", "high", "https://b.example", "m2"),
        ],
        removed=[
            DiffFinding("fp3", "MISSING_XFO", "low", "https://c.example", "m3"),
        ],
        unchanged=[],
    )
    publisher = RecordingPublisher()
    options = AlertOptions(
        min_severity="medium",
        rule_ids=["MISSING_HSTS", "MISSING_CSP"],
        uri_regex=r"https://(a|b)\.example",
        max_events=1,
        state_path=str(tmp_path / "state.json"),
    )

    result = dispatch_diff_alerts(
        diff,
        publisher,
        engagement_id="eng",
        run_id="run-1",
        old_path="old.sarif",
        new_path="new.sarif",
        options=options,
        dry_run=False,
    )

    assert result.considered == 2
    assert result.published == 1
    assert len(publisher.events) == 2
    assert publisher.events[0]["event_type"] == "finding_added"
    assert publisher.events[0]["rule_id"] == "MISSING_HSTS"
    assert publisher.events[1]["event_type"] == "alert_summary"


def test_dispatch_diff_alerts_respects_cooldown(tmp_path) -> None:
    diff = DiffResult(
        added=[DiffFinding("fp1", "MISSING_CSP", "medium", "https://a.example", "m1")],
        removed=[],
        unchanged=[],
    )
    publisher = RecordingPublisher()
    state_path = tmp_path / "state.json"
    options = AlertOptions(cooldown_minutes=60, state_path=str(state_path))

    first = dispatch_diff_alerts(
        diff,
        publisher,
        engagement_id="eng",
        run_id="run-1",
        old_path="old.sarif",
        new_path="new.sarif",
        options=options,
        dry_run=False,
    )
    second = dispatch_diff_alerts(
        diff,
        publisher,
        engagement_id="eng",
        run_id="run-2",
        old_path="old.sarif",
        new_path="new.sarif",
        options=options,
        dry_run=False,
    )

    assert first.published == 1
    assert second.published == 0
    assert second.suppressed_by_cooldown == 1
    summaries = [event for event in publisher.events if event.get("event_type") == "alert_summary"]
    assert len(summaries) == 2
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "finding_added:fp1" in state
