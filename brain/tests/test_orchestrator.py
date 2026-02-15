import json
from pathlib import Path

from brain.adapters.evidence_store_fs import FileSystemEvidenceStore
from brain.adapters.publisher_noop import NoopPublisher
from brain.core.models import Evidence, Finding, ToolRequest, ToolResult
from brain.core.orchestrator import Orchestrator
from brain.core.version import get_casm_version


class FakeToolGateway:
    def __init__(self, fixture_path: str) -> None:
        self.fixture_path = fixture_path

    def run(self, request: ToolRequest) -> ToolResult:
        with open(self.fixture_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        findings = [Finding(**item) for item in raw["findings"]]
        evidence = [Evidence(**item) for item in raw["evidence"]]
        return ToolResult(
            ok=raw["ok"],
            blocked_reason=raw["blocked_reason"],
            findings=findings,
            evidence=evidence,
            metrics=raw.get("metrics", {}),
            raw_redacted=raw.get("raw_redacted"),
            tool_name=raw.get("tool_name"),
            tool_version=raw.get("tool_version"),
        )


def test_orchestrator_writes_report_and_evidence(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        f"""
engagement_id: eng-123
allowed_domains:
  - example.com
allowed_ips: []
allowed_ports: [80, 443]
allowed_protocols: [tcp]
seed_targets: [example.com]
max_rate: 5
max_concurrency: 2
run_dir: {tmp_path}/runs
active_allowed: false
auth_allowed: false
""",
        encoding="utf-8",
    )

    gateway = FakeToolGateway("contracts/fixtures/probe_response.json")
    evidence_store = FileSystemEvidenceStore(base_dir=str(tmp_path / "runs"))
    orchestrator = Orchestrator(gateway, evidence_store, NoopPublisher())
    summary = orchestrator.run(scope_path=str(scope_path), dry_run=False)

    assert summary["findings"] == 1
    report_path = summary["report_path"]
    evidence_path = summary["evidence_path"]
    report = Path(report_path).read_text(encoding="utf-8")
    evidence = Path(evidence_path).read_text(encoding="utf-8").splitlines()
    assert "Scan Telemetry" in report
    assert "Endpoints attempted: 2" in report
    assert "Hosts assessed" in report
    assert "highest severity" in report
    assert "Assets Observed" in report
    assert report.index("## Scope & Method") < report.index("## Limitations")
    assert report.index("## Limitations") < report.index("## Findings")
    assert report.index("## Executive Summary") < report.index("## Technical Summary")
    assert report.index("## Scope & Method") < report.index("## Findings")
    assert report.index("## Findings") < report.index("## Scan Telemetry")
    assert "Scope & Method" in report
    assert "Per-attempt timeout" in report
    assert "Tool timeout" in report
    assert "evi-1" in evidence[0]
    evidence_items = [json.loads(line) for line in evidence]
    assert evidence_items[0]["engagement_id"] == "eng-123"
    assert evidence_items[0]["run_id"] == summary["run_id"]
    assert evidence_items[0]["tool_name"] == "probe"
    statuses = {item["status"] for item in evidence_items}
    assert "success" in statuses
    assert "error" in statuses
    sarif = json.loads(Path(summary["sarif_path"]).read_text(encoding="utf-8"))
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "CASM"
    first_result = sarif["runs"][0]["results"][0]
    assert "ruleId" in first_result
    assert "message" in first_result
    assert "locations" in first_result


def test_attempts_match_ports_without_retries(tmp_path) -> None:
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        f"""
engagement_id: eng-123
allowed_domains:
  - example.com
allowed_ips: []
allowed_ports: [80, 81, 443]
allowed_protocols: [tcp]
seed_targets: [example.com]
max_rate: 5
max_concurrency: 1
run_dir: {tmp_path}/runs
active_allowed: false
auth_allowed: false
""",
        encoding="utf-8",
    )

    version = get_casm_version()

    class CountingGateway:
        def run(self, request: ToolRequest) -> ToolResult:
            evidence = []
            for port in request.input["ports"]:
                evidence.append(
                    Evidence(
                        id=f"evi-{port}",
                        timestamp="2026-01-27T00:00:00Z",
                        type="tcp_connect",
                        target=f"example.com:{port}",
                        data={"protocol": "tcp", "port": port},
                        status="error",
                        duration_ms=1,
                    )
                )
            return ToolResult(
                ok=True,
                blocked_reason=None,
                findings=[],
                evidence=evidence,
                metrics={"duration_ms": 1},
                tool_name="probe",
                tool_version=version,
            )

    gateway = CountingGateway()
    evidence_store = FileSystemEvidenceStore(base_dir=str(tmp_path / "runs"))
    orchestrator = Orchestrator(gateway, evidence_store, NoopPublisher())
    summary = orchestrator.run(scope_path=str(scope_path), dry_run=False)

    evidence_lines = Path(summary["evidence_path"]).read_text(encoding="utf-8").splitlines()
    evidence_items = [json.loads(line) for line in evidence_lines]
    tcp_events = [item for item in evidence_items if item["type"] == "tcp_connect"]
    assert len(tcp_events) == 3
    sarif = json.loads(Path(summary["sarif_path"]).read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_blocked_run_writes_run_result_and_stderr(tmp_path) -> None:
    version = get_casm_version()
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        f"""
engagement_id: eng-123
allowed_domains:
  - example.com
allowed_ips: []
allowed_ports: [80]
allowed_protocols: [tcp]
seed_targets: [example.com]
max_rate: 5
max_concurrency: 2
run_dir: {tmp_path}/runs
active_allowed: false
auth_allowed: false
""",
        encoding="utf-8",
    )

    class BlockedGateway:
        def run(self, request: ToolRequest) -> ToolResult:
            return ToolResult(
                ok=False,
                blocked_reason="tool_timeout",
                findings=[],
                evidence=[],
                metrics={"duration_ms": 2000},
                raw_redacted={"stderr": "timeout", "stdout": "partial"},
                tool_name="probe",
                tool_version=None,
            )

    gateway = BlockedGateway()
    evidence_store = FileSystemEvidenceStore(base_dir=str(tmp_path / "runs"))
    orchestrator = Orchestrator(gateway, evidence_store, NoopPublisher())
    summary = orchestrator.run(scope_path=str(scope_path), dry_run=False)

    evidence_path = summary["evidence_path"]
    evidence_lines = Path(evidence_path).read_text(encoding="utf-8").splitlines()
    assert evidence_lines
    evidence_items = [json.loads(line) for line in evidence_lines]
    run_items = [item for item in evidence_items if item["type"] == "run_result"]
    assert len(run_items) == 1
    run_item = run_items[0]
    assert run_item["status"] == "blocked"
    assert run_item["data"]["blocked_reason"] == "tool_timeout"
    assert "stderr_path" in run_item["data"]
    assert "stdout_path" in run_item["data"]
    assert run_item["tool_version"] == version
    assert Path(run_item["data"]["stderr_path"]).exists()
    assert Path(run_item["data"]["stdout_path"]).exists()
