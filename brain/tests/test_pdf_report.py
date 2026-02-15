from __future__ import annotations

import json
from pathlib import Path

from brain.core.pdf_report import calculate_summary_stats, generate_pdf_report, _find_baseline_info


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def _write_sarif(path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "MISSING_HSTS",
                        "level": "warning",
                        "message": {"text": "Missing HSTS header."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://example.com"}}}
                        ],
                        "properties": {"severity": "high", "finding_fingerprint": "abc123"},
                    },
                    {
                        "ruleId": "HTTP_NOT_HTTPS",
                        "level": "warning",
                        "message": {"text": "HTTP endpoint."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "http://example.com"}}}
                        ],
                        "properties": {"severity": "medium", "finding_fingerprint": "def456"},
                    },
                ]
            }
        ],
    }
    path.write_text(json.dumps(sarif), encoding="utf-8")


def test_calculate_summary_stats(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    targets_path = tmp_path / "targets.jsonl"
    sarif_path = tmp_path / "results.sarif"

    _write_jsonl(
        evidence_path,
        [
            {
                "type": "dns_discovery",
                "timestamp": "2025-01-01T00:00:00Z",
                "data": {"subdomain": "app.example.com", "record_type": "A", "values": ["1.2.3.4"], "source": "crt.sh"},
            },
            {
                "type": "http_attempt",
                "timestamp": "2025-01-01T00:00:10Z",
            },
            {
                "type": "tcp_connect",
                "timestamp": "2025-01-01T00:00:15Z",
                "target": "example.com:443",
                "data": {"port": 443, "protocol": "tcp"},
                "status": "success",
            },
        ],
    )

    _write_jsonl(
        targets_path,
        [
            {"target": "example.com:443", "host": "example.com"},
            {"target": "app.example.com:443", "host": "app.example.com"},
        ],
    )

    _write_sarif(sarif_path)

    summary = calculate_summary_stats(evidence_path, targets_path, sarif_path)
    assert summary.domains_scanned == 2
    assert summary.http_attempts == 1
    assert len(summary.dns_discoveries) == 1
    assert summary.severity_counts["high"] == 1
    assert summary.severity_counts["medium"] == 1


def test_generate_pdf_report_creates_file(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    targets_path = tmp_path / "targets.jsonl"
    sarif_path = tmp_path / "results.sarif"

    _write_jsonl(
        evidence_path,
        [
            {"type": "http_attempt", "timestamp": "2025-01-01T00:00:00Z"},
            {"type": "tcp_connect", "timestamp": "2025-01-01T00:00:01Z", "target": "example.com:80"},
        ],
    )
    _write_jsonl(targets_path, [{"target": "example.com:80", "host": "example.com"}])
    _write_sarif(sarif_path)

    pdf_path = generate_pdf_report(
        engagement_id="eng-001",
        run_id="run-001",
        output_dir=tmp_path,
        evidence_store=None,
        branding_config={"primary_color": "#zzzzzz", "logo_path": str(tmp_path / "missing.png")},
    )
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0


def test_find_baseline_info_picks_latest(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "runs" / "eng-001"
    engagement_dir.mkdir(parents=True)
    older = engagement_dir / "20260101T010101Z-aaaa"
    newer = engagement_dir / "20260102T010101Z-bbbb"
    older.mkdir()
    newer.mkdir()
    _write_sarif(older / "results.sarif")
    _write_sarif(newer / "results.sarif")

    baseline = _find_baseline_info("eng-001", "20260103T010101Z-cccc", engagement_dir)
    assert baseline is not None
    assert baseline.run_id == "20260102T010101Z-bbbb"
