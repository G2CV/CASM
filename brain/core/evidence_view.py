
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EvidenceFilter:
    event_type: str | None = None
    tool_name: str | None = None
    target_id: str | None = None
    contains: str | None = None
    contains_scope: str = "all"
    ignore_case: bool = False
    strict: bool = False
    since: datetime | None = None
    until: datetime | None = None
    limit: int = 50


@dataclass
class EvidenceLoadStats:
    invalid_json_lines: int = 0
    skipped_missing_timestamp: int = 0
    skipped_bad_timestamp: int = 0


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps while normalizing to UTC.

    Args:
        value (str): Timestamp in ISO-8601 format.

    Returns:
        datetime: Parsed timestamp with timezone information.

    Raises:
        ValueError: If the timestamp is not valid ISO-8601.
    """
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


class EvidenceStream:
    """Streaming evidence reader with lazy filtering and stats."""
    def __init__(self, path: str, filters: EvidenceFilter) -> None:
        self._path = path
        self._filters = filters
        self.stats = EvidenceLoadStats()

    def __iter__(self):
        emitted = 0
        with Path(self._path).open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    if self._filters.strict:
                        raise
                    self.stats.invalid_json_lines += 1
                    continue
                if self._filters.event_type and event.get("type") != self._filters.event_type:
                    continue
                if self._filters.tool_name and event.get("tool_name") != self._filters.tool_name:
                    continue
                if self._filters.target_id and event.get("target_id") != self._filters.target_id:
                    continue
                if self._filters.since or self._filters.until:
                    timestamp = event.get("timestamp")
                    if not timestamp:
                        if self._filters.strict:
                            raise ValueError("Missing event timestamp")
                        self.stats.skipped_missing_timestamp += 1
                        continue
                    try:
                        parsed_timestamp = parse_timestamp(str(timestamp))
                    except ValueError:
                        if self._filters.strict:
                            raise ValueError(f"Invalid event timestamp: {timestamp}")
                        self.stats.skipped_bad_timestamp += 1
                        continue
                    if self._filters.since and parsed_timestamp < self._filters.since:
                        continue
                    if self._filters.until and parsed_timestamp > self._filters.until:
                        continue
                if self._filters.contains and not _contains_match(event, line, self._filters):
                    continue
                yield event
                emitted += 1
                if self._filters.limit and emitted >= self._filters.limit:
                    break


def load_evidence(path: str, filters: EvidenceFilter) -> EvidenceStream:
    """Create a streaming evidence reader to avoid loading large files.

    Args:
        path (str): Evidence JSONL path.
        filters (EvidenceFilter): Filters and limits to apply.

    Returns:
        EvidenceStream: Iterable evidence stream with stats.
    """
    return EvidenceStream(path, filters)


def _contains_match(event: dict, raw_line: str, filters: EvidenceFilter) -> bool:
    needle = filters.contains or ""
    if filters.ignore_case:
        needle = needle.lower()

    def match(value: str) -> bool:
        haystack = value
        if filters.ignore_case:
            haystack = value.lower()
        return needle in haystack

    scope = filters.contains_scope
    if scope == "all":
        return match(raw_line)
    if scope == "message":
        return match(str(event.get("message", "")))
    if scope == "error":
        data = event.get("data", {}) if isinstance(event.get("data", {}), dict) else {}
        return match(str(data.get("error", ""))) or match(str(event.get("error", "")))
    if scope == "data":
        data = event.get("data", {}) if isinstance(event.get("data", {}), dict) else {}
        return match(json.dumps(data, sort_keys=True, separators=(",", ":")))
    return match(raw_line)
