from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from brain.core.diff import DiffFinding, DiffResult
from brain.ports.publisher import Publisher


SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


@dataclass
class AlertOptions:
    min_severity: str = "low"
    rule_ids: list[str] | None = None
    uri_regex: str | None = None
    cooldown_minutes: int = 0
    max_events: int = 50
    include_added: bool = True
    include_removed: bool = True
    state_path: str | None = None


@dataclass
class AlertDispatchResult:
    considered: int
    published: int
    suppressed_by_cooldown: int
    skipped_by_filters: int


def dispatch_diff_alerts(
    diff: DiffResult,
    publisher: Publisher,
    *,
    engagement_id: str,
    run_id: str,
    old_path: str,
    new_path: str,
    options: AlertOptions,
    dry_run: bool,
) -> AlertDispatchResult:
    now = datetime.now(timezone.utc)
    events = _build_diff_events(diff, options)
    considered = len(events)

    if options.max_events >= 0:
        events = events[: options.max_events]

    cooldown_state = _load_state(options.state_path)
    published_events: list[dict] = []
    suppressed = 0
    for event in events:
        if _in_cooldown(event, cooldown_state, options.cooldown_minutes, now):
            suppressed += 1
            continue
        published_events.append(event)

    if not dry_run:
        for event in published_events:
            publisher.publish(event)

    for event in published_events:
        cooldown_state[_cooldown_key(event)] = int(now.timestamp())
    _save_state(options.state_path, cooldown_state)

    skipped_by_filters = considered - len(published_events) - suppressed
    if skipped_by_filters < 0:
        skipped_by_filters = 0

    summary = {
        "event_type": "alert_summary",
        "timestamp": _iso_now(),
        "engagement_id": engagement_id,
        "run_id": run_id,
        "source": "casm.diff",
        "old_path": old_path,
        "new_path": new_path,
        "considered": considered,
        "published": len(published_events),
        "suppressed_by_cooldown": suppressed,
        "skipped_by_filters": skipped_by_filters,
        "dry_run": dry_run,
    }
    if not dry_run:
        publisher.publish(summary)

    return AlertDispatchResult(
        considered=considered,
        published=len(published_events),
        suppressed_by_cooldown=suppressed,
        skipped_by_filters=skipped_by_filters,
    )


def _build_diff_events(diff: DiffResult, options: AlertOptions) -> list[dict]:
    threshold = SEVERITY_RANK.get(options.min_severity.lower(), SEVERITY_RANK["low"])
    rule_allow = {rule.strip() for rule in (options.rule_ids or []) if rule.strip()}
    uri_pattern = re.compile(options.uri_regex) if options.uri_regex else None

    findings: list[tuple[str, DiffFinding]] = []
    if options.include_added:
        findings.extend(("finding_added", item) for item in diff.added)
    if options.include_removed:
        findings.extend(("finding_removed", item) for item in diff.removed)

    findings.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item[1].severity, SEVERITY_RANK["unknown"]),
            item[1].rule_id,
            item[1].uri,
            item[0],
        )
    )

    events: list[dict] = []
    for event_type, finding in findings:
        rank = SEVERITY_RANK.get(finding.severity, SEVERITY_RANK["unknown"])
        if rank > threshold:
            continue
        if rule_allow and finding.rule_id not in rule_allow:
            continue
        if uri_pattern and not uri_pattern.search(finding.uri):
            continue
        events.append(
            {
                "event_type": event_type,
                "timestamp": _iso_now(),
                "source": "casm.diff",
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "uri": finding.uri,
                "message": finding.message,
            }
        )
    return events


def _cooldown_key(event: dict) -> str:
    return f"{event.get('event_type', '')}:{event.get('fingerprint', '')}"


def _in_cooldown(event: dict, state: dict[str, int], cooldown_minutes: int, now: datetime) -> bool:
    if cooldown_minutes <= 0:
        return False
    key = _cooldown_key(event)
    last = state.get(key)
    if last is None:
        return False
    return int(now.timestamp()) - int(last) < cooldown_minutes * 60


def _load_state(path: str | None) -> dict[str, int]:
    if not path:
        return {}
    file_path = Path(path)
    if not file_path.exists():
        return {}
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict):
        return {}
    state: dict[str, int] = {}
    for key, value in payload.items():
        if isinstance(key, str) and isinstance(value, int):
            state[key] = value
    return state


def _save_state(path: str | None, state: dict[str, int]) -> None:
    if not path:
        return
    file_path = Path(path)
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(json.dumps(state, sort_keys=True, indent=2), encoding="utf-8")
    except OSError:
        return


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
