import json

import pytest

from brain.core.evidence_view import EvidenceFilter, load_evidence, parse_timestamp


def test_load_evidence_filters(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "type": "http_attempt", "tool_name": "http_verify", "target_id": "t1"},
        {"id": "2", "type": "http_response", "tool_name": "http_verify", "target_id": "t1"},
        {"id": "3", "type": "tcp_connect", "tool_name": "probe", "target_id": "t2"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    filtered = list(
        load_evidence(
            str(evidence_path),
            EvidenceFilter(event_type="http_response", tool_name="http_verify", limit=10),
        )
    )
    assert len(filtered) == 1
    assert filtered[0]["id"] == "2"


def test_contains_whole_line_matches_nested_fields(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {
            "id": "1",
            "type": "http_response",
            "data": {"final_url": "https://localhost:8444/health"},
        },
        {"id": "2", "type": "http_response", "data": {"final_url": "https://example.com"}},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    filtered = list(
        load_evidence(
            str(evidence_path),
            EvidenceFilter(contains="localhost:8444", limit=10),
        )
    )

    assert len(filtered) == 1
    assert filtered[0]["id"] == "1"


def test_contains_message_scope_does_not_match_nested_fields(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {
            "id": "1",
            "type": "http_response",
            "data": {"final_url": "https://localhost:8444/health"},
        },
        {"id": "2", "type": "http_response", "message": "ok"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    filtered = list(
        load_evidence(
            str(evidence_path),
            EvidenceFilter(contains="localhost:8444", contains_scope="message", limit=10),
        )
    )

    assert filtered == []


def test_contains_error_scope_matches_http_error_data(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {
            "id": "1",
            "type": "http_error",
            "data": {"error": "tls: handshake failure"},
        },
        {"id": "2", "type": "http_error", "data": {"error": "timeout"}},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    filtered = list(
        load_evidence(
            str(evidence_path),
            EvidenceFilter(contains="tls:", contains_scope="error", limit=10),
        )
    )

    assert len(filtered) == 1
    assert filtered[0]["id"] == "1"


def test_since_only_includes_at_or_after_bound(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "timestamp": "2026-02-01T10:00:00Z"},
        {"id": "2", "timestamp": "2026-02-01T10:00:01Z"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    stream = load_evidence(
        str(evidence_path),
        EvidenceFilter(since=parse_timestamp("2026-02-01T10:00:01Z"), limit=10),
    )
    filtered = list(stream)

    assert [item["id"] for item in filtered] == ["2"]


def test_until_only_includes_at_or_before_bound(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "timestamp": "2026-02-01T10:00:00Z"},
        {"id": "2", "timestamp": "2026-02-01T10:00:01Z"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    stream = load_evidence(
        str(evidence_path),
        EvidenceFilter(until=parse_timestamp("2026-02-01T10:00:00Z"), limit=10),
    )
    filtered = list(stream)

    assert [item["id"] for item in filtered] == ["1"]


def test_since_until_window_includes_only_within_bounds(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "timestamp": "2026-02-01T10:00:00Z"},
        {"id": "2", "timestamp": "2026-02-01T10:00:01Z"},
        {"id": "3", "timestamp": "2026-02-01T10:00:02Z"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    stream = load_evidence(
        str(evidence_path),
        EvidenceFilter(
            since=parse_timestamp("2026-02-01T10:00:01Z"),
            until=parse_timestamp("2026-02-01T10:00:02Z"),
            limit=10,
        ),
    )
    filtered = list(stream)

    assert [item["id"] for item in filtered] == ["2", "3"]


def test_invalid_timestamp_format_errors() -> None:
    with pytest.raises(ValueError, match="Invalid timestamp"):
        parse_timestamp("not-a-timestamp")


def test_limit_stops_early(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "type": "http_response", "message": "hit"},
        {"id": "2", "type": "http_response", "message": "hit"},
        {"id": "3", "type": "http_response", "message": "hit"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    filtered = list(
        load_evidence(
            str(evidence_path),
            EvidenceFilter(contains="hit", contains_scope="message", limit=2),
        )
    )

    assert [item["id"] for item in filtered] == ["1", "2"]


def test_missing_field_does_not_error(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "type": "http_response"},
        {"id": "2", "type": "http_error", "data": {}},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    filtered = list(
        load_evidence(
            str(evidence_path),
            EvidenceFilter(contains="tls:", contains_scope="error", limit=10),
        )
    )

    assert filtered == []


def test_missing_or_bad_timestamp_skips_non_strict(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1", "timestamp": "2026-02-01T10:00:00Z"},
        {"id": "2"},
        {"id": "3", "timestamp": "bad"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    stream = load_evidence(
        str(evidence_path),
        EvidenceFilter(since=parse_timestamp("2026-02-01T10:00:00Z"), limit=10),
    )
    filtered = list(stream)

    assert [item["id"] for item in filtered] == ["1"]
    assert stream.stats.skipped_missing_timestamp == 1
    assert stream.stats.skipped_bad_timestamp == 1


def test_missing_or_bad_timestamp_strict_raises(tmp_path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    events = [
        {"id": "1"},
        {"id": "2", "timestamp": "bad"},
    ]
    evidence_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    stream = load_evidence(
        str(evidence_path),
        EvidenceFilter(since=parse_timestamp("2026-02-01T10:00:00Z"), strict=True, limit=10),
    )

    with pytest.raises(ValueError):
        list(stream)
