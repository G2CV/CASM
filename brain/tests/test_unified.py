import json
from pathlib import Path

import pytest

from brain.core.models import Finding, ToolResult
from brain.core.scope import Scope
from brain.core.unified import (
    build_import_inventory,
    derive_http_targets,
    load_targets_file,
    normalize_targets,
    render_unified_report,
    run_unified,
    write_unified_sarif,
)


def test_derive_http_targets_dedupes_and_orders() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[80, 8443],
        allowed_protocols=["http", "https"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
        http_verify_https_ports=[8443],
    )
    scope.allowed_protocols = ["http", "https", "tcp"]
    probe_result = ToolResult(
        ok=True,
        blocked_reason=None,
        findings=[
            Finding(
                id="f1",
                title="Open TCP port",
                severity="low",
                target="example.com:80",
                evidence_ids=["e1"],
                summary="open",
                timestamp="2026-01-01T00:00:00Z",
            ),
            Finding(
                id="f2",
                title="Open TCP port",
                severity="low",
                target="example.com:8443",
                evidence_ids=["e2"],
                summary="open",
                timestamp="2026-01-01T00:00:01Z",
            ),
        ],
    )

    targets = derive_http_targets(scope, probe_result)
    assert targets == [
        {"url": "http://example.com:80/", "method": "HEAD"},
        {"url": "https://example.com:80/", "method": "HEAD"},
        {"url": "https://example.com:8443/", "method": "HEAD"},
    ]


def test_write_unified_sarif_github_mode(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    probe_result = ToolResult(
        ok=True,
        blocked_reason=None,
        findings=[],
        tool_name="probe",
        tool_version="dev",
    )

    http_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CASM"}}, "results": []}],
    }
    http_path = tmp_path / "http.sarif"
    http_path.write_text(json.dumps(http_sarif), encoding="utf-8")

    sarif_path, probe_path, http_out, dns_out = write_unified_sarif(
        tmp_path,
        scope,
        "run-1",
        "github",
        probe_result,
        str(http_path),
    )

    assert probe_path and http_out
    assert dns_out is None
    assert Path(probe_path).exists()
    assert Path(http_out).exists()
    data = json.loads(Path(probe_path).read_text(encoding="utf-8"))
    assert len(data["runs"]) == 1


def test_load_targets_file_requires_targets_array(tmp_path) -> None:
    targets_path = tmp_path / "targets.json"
    targets_path.write_text(json.dumps({"items": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="targets"):
        load_targets_file(str(targets_path))


def test_load_targets_file_requires_url(tmp_path) -> None:
    targets_path = tmp_path / "targets.json"
    targets_path.write_text(json.dumps({"targets": [{"method": "HEAD"}]}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing url"):
        load_targets_file(str(targets_path))


def test_normalize_targets_dedupes_and_orders() -> None:
    raw_targets = [
        {"url": "https://example.com/path", "method": "get"},
        {"url": "https://example.com/path", "method": "GET"},
        {"url": "https://example.com:443/", "method": "HEAD"},
    ]

    normalized = normalize_targets(raw_targets)
    assert normalized == [
        {"url": "https://example.com:443/", "method": "HEAD"},
        {"url": "https://example.com:443/path", "method": "GET"},
    ]


def test_build_import_inventory_blocks_out_of_scope(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[443],
        allowed_protocols=["https"],
        seed_targets=[],
        max_rate=1.0,
        max_concurrency=1,
    )
    targets = normalize_targets(
        [
            {"url": "https://example.com/", "method": "HEAD"},
            {"url": "https://other.com/", "method": "HEAD"},
        ]
    )

    inventory, allowed_targets, summary = build_import_inventory(
        scope,
        targets,
        "targets.json",
        total_targets=2,
    )

    assert len(allowed_targets) == 1
    assert summary.allowed_targets == 1
    assert summary.blocked_targets == 1
    assert any(record.allowed is False for record in inventory)
    assert all(record.source == "import" for record in inventory)
    assert all(record.source_path == "targets.json" for record in inventory)


def test_normalize_targets_is_deterministic() -> None:
    targets_a = [
        {"url": "https://b.example.com:443/path", "method": "HEAD"},
        {"url": "https://a.example.com/", "method": "HEAD"},
    ]
    targets_b = list(reversed(targets_a))

    assert normalize_targets(targets_a) == normalize_targets(targets_b)


def test_run_unified_import_mode_writes_artifacts(tmp_path, monkeypatch) -> None:
    class FakeHttpVerifyGateway:
        def __init__(self, tool_path: str, timeout_ms: int) -> None:
            self.tool_path = tool_path
            self.timeout_ms = timeout_ms

        def run(self, payload: dict) -> dict:
            evidence_path = payload["evidence"]["jsonl_path"]
            sarif_path = payload["sarif"]["path"]
            targets = payload.get("targets", [])
            evidence_lines = []
            for index, target in enumerate(targets, start=1):
                evidence_lines.append(
                    json.dumps(
                        {
                            "id": f"e{index}",
                            "timestamp": "2026-02-01T00:00:00Z",
                            "type": "http_attempt",
                            "data": {"url": target["url"], "method": target["method"]},
                        }
                    )
                )
            Path(evidence_path).write_text("\n".join(evidence_lines), encoding="utf-8")
            sarif = {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "CASM"}}, "results": []}],
            }
            Path(sarif_path).write_text(json.dumps(sarif), encoding="utf-8")
            return {"summary": {"targets": len(targets)}}

    monkeypatch.setattr(
        "brain.core.unified.HttpVerifyGateway",
        FakeHttpVerifyGateway,
    )

    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[443],
        allowed_protocols=["https"],
        seed_targets=[],
        max_rate=1.0,
        max_concurrency=1,
    )
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(scope.__dict__), encoding="utf-8")

    targets_path = tmp_path / "targets.json"
    targets_path.write_text(
        json.dumps({"targets": [{"url": "https://example.com/", "method": "HEAD"}]}),
        encoding="utf-8",
    )

    outputs = run_unified(
        scope_path=str(scope_path),
        out_dir=str(tmp_path / "out"),
        sarif_mode="local",
        probe_tool_path="/bin/false",
        http_tool_path="/bin/false",
        dry_run=True,
        targets_file=str(targets_path),
    )

    assert Path(outputs.targets_path).exists()
    assert Path(outputs.evidence_path).exists()
    assert Path(outputs.sarif_path).exists()
    assert Path(outputs.report_path).exists()


def test_render_unified_report_includes_http_counts(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [],
            }
        ),
        encoding="utf-8",
    )
    probe_result = ToolResult(ok=True, blocked_reason=None, findings=[])
    evidence = [
        {"type": "http_attempt"},
        {"type": "http_response"},
        {"type": "http_error"},
        {"type": "http_blocked"},
    ]

    report = render_unified_report(
        scope,
        "run-1",
        probe_result,
        str(sarif_path),
        evidence,
        expected_http_targets=1,
    )

    assert "HTTP attempts observed: 1." in report
    assert "HTTP responses observed: 1." in report
    assert "HTTP errors observed: 1." in report
    assert "HTTP blocked observed: 1." in report
    assert "Warning: http_verify completed fewer targets" not in report


def test_render_unified_report_aggregates_http_findings(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "MISSING_CSP",
                                "message": {"text": "Missing CSP."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "https://example.com/a"}
                                        }
                                    }
                                ],
                                "properties": {"finding_fingerprint": "fp-1", "severity": "medium"},
                            },
                            {
                                "ruleId": "MISSING_CSP",
                                "message": {"text": "Missing CSP."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "https://example.com/b"}
                                        }
                                    }
                                ],
                                "properties": {"finding_fingerprint": "fp-2", "severity": "medium"},
                            },
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    probe_result = ToolResult(ok=True, blocked_reason=None, findings=[])
    evidence = [
        {
            "id": "e1",
            "timestamp": "2026-02-02T00:00:01Z",
            "type": "http_response",
            "data": {"finding_fingerprint": "fp-1"},
        },
        {
            "id": "e2",
            "timestamp": "2026-02-02T00:00:02Z",
            "type": "http_response",
            "data": {"finding_fingerprint": "fp-2"},
        },
    ]

    report = render_unified_report(
        scope,
        "run-1",
        probe_result,
        str(sarif_path),
        evidence,
    )

    assert "MISSING_CSP (2 endpoints affected) — medium" in report
    assert "First detected: 2026-02-02T00:00:01Z" in report
    assert "Last detected: 2026-02-02T00:00:02Z" in report


def test_render_unified_report_detailed_flag(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "MISSING_CSP",
                                "message": {"text": "Missing CSP."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "https://example.com/a"}
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    probe_result = ToolResult(ok=True, blocked_reason=None, findings=[])

    report = render_unified_report(
        scope,
        "run-1",
        probe_result,
        str(sarif_path),
        [],
        detailed_report=True,
    )

    assert "Findings (http_verify, detailed)" in report


def test_render_unified_report_warns_on_incomplete_targets(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [],
            }
        ),
        encoding="utf-8",
    )
    probe_result = ToolResult(ok=True, blocked_reason=None, findings=[])
    evidence = [{"type": "http_attempt"}]

    report = render_unified_report(
        scope,
        "run-1",
        probe_result,
        str(sarif_path),
        evidence,
        expected_http_targets=3,
    )

    assert "Warning: http_verify completed fewer targets" in report


def test_render_unified_report_supports_french(tmp_path) -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [],
            }
        ),
        encoding="utf-8",
    )
    probe_result = ToolResult(ok=True, blocked_reason=None, findings=[])
    report = render_unified_report(
        scope,
        "run-1",
        probe_result,
        str(sarif_path),
        [],
        report_lang="fr",
    )

    assert "# Rapport unifié CASM" in report
    assert "## Résumé exécutif" in report
    assert "## Périmètre et méthode" in report
