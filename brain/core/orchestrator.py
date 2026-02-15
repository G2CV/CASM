
from __future__ import annotations

import math
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone

from brain.core.inventory import build_probe_inventory, write_inventory
from brain.core.models import Evidence, ToolRequest, ToolResult
from brain.core.report import render_report
from brain.core.schema_version import SCHEMA_VERSION
from brain.core.sarif import build_sarif
from brain.core.scope import Scope
from brain.core.version import get_casm_version
from brain.ports.evidence_store import EvidenceStore
from brain.ports.publisher import Publisher
from brain.ports.tool_gateway import ToolGateway


class Orchestrator:
    def __init__(
        self,
        tool_gateway: ToolGateway,
        evidence_store: EvidenceStore,
        publisher: Publisher,
    ) -> None:
        self.tool_gateway = tool_gateway
        self.evidence_store = evidence_store
        self.publisher = publisher

    def run(self, scope_path: str, dry_run: bool) -> dict:
        """Run the probe pipeline end-to-end and persist artifacts.

        Args:
            scope_path (str): Path to the scope configuration file.
            dry_run (bool): When True, executes a policy-only pass without scans.

        Returns:
            dict: Summary with run metadata and artifact paths.

        Notes:
            The tool timeout is raised to a conservative estimate so a wide
            port list doesn't fail prematurely under normal latency.
        """
        scope = Scope.from_file(scope_path)
        run_id = self._new_run_id()

        ports = scope.allowed_ports
        per_attempt_timeout_ms = int(scope.per_attempt_timeout_ms)
        tool_timeout_ms = int(scope.tool_timeout_ms)
        estimated = int(math.ceil(len(ports) / max(scope.max_concurrency, 1)) * per_attempt_timeout_ms + 500)
        if tool_timeout_ms < estimated:
            tool_timeout_ms = estimated

        run_dir = Path("runs") / scope.engagement_id / run_id
        if scope.snapshot().get("run_dir"):
            run_dir = Path(scope.snapshot()["run_dir"]) / scope.engagement_id / run_id
        inventory = build_probe_inventory(scope)
        write_inventory(str(run_dir / "targets.jsonl"), inventory)

        request = ToolRequest(
            tool_name="probe",
            engagement_id=scope.engagement_id,
            run_id=run_id,
            scope_snapshot=scope.snapshot(),
            dry_run=dry_run,
            per_attempt_timeout_ms=per_attempt_timeout_ms,
            tool_timeout_ms=tool_timeout_ms,
            rate_limit={
                "rps": scope.max_rate,
                "burst": int(scope.max_rate),
                "concurrency": scope.max_concurrency,
            },
            input={
                "targets": [{"host": host} for host in scope.seed_targets],
                "ports": ports,
                "protocol": "tcp",
            },
        )

        result: ToolResult = self.tool_gateway.run(request)
        run_status = "success" if result.ok and not result.blocked_reason else "error"
        if result.blocked_reason:
            run_status = "blocked"

        tool_name = result.tool_name or request.tool_name
        tool_version = result.tool_version
        if tool_name == "probe" and not tool_version:
            tool_version = get_casm_version()

        run_evidence = _build_run_result_evidence(
            scope.engagement_id,
            run_id,
            tool_name,
            tool_version,
            run_status,
            result.metrics.get("duration_ms", 0),
            result.blocked_reason,
        )

        evidence = list(result.evidence)
        evidence.append(run_evidence)
        report_md = render_report(
            scope,
            run_id,
            result.findings,
            evidence,
            result.blocked_reason,
            dry_run,
        )
        tool_stderr = None
        tool_stdout = None
        if result.blocked_reason == "tool_timeout":
            tool_stderr = result.raw_redacted.get("stderr") if result.raw_redacted else ""
            tool_stdout = result.raw_redacted.get("stdout") if result.raw_redacted else ""

        output_paths = self.evidence_store.write(
            scope.engagement_id,
            run_id,
            tool_name,
            tool_version,
            result.findings,
            evidence,
            report_md,
            tool_stderr,
            tool_stdout,
        )

        sarif = build_sarif(
            result.findings,
            scope.engagement_id,
            run_id,
            tool_name,
            tool_version or get_casm_version(),
        )
        sarif_path = Path(output_paths["report"]).parent / "results.sarif"
        sarif_path.write_text(json.dumps(sarif, indent=2, sort_keys=True), encoding="utf-8")

        if result.blocked_reason == "tool_timeout":
            if output_paths.get("tool_stderr"):
                run_evidence.data["stderr_path"] = output_paths["tool_stderr"]
            if output_paths.get("tool_stdout"):
                run_evidence.data["stdout_path"] = output_paths["tool_stdout"]
            evidence[-1] = run_evidence
            self.evidence_store.write(
                scope.engagement_id,
                run_id,
                tool_name,
                tool_version,
                result.findings,
                evidence,
                report_md,
                None,
                None,
            )

        run_summary = {
            "engagement_id": scope.engagement_id,
            "run_id": run_id,
            "findings": len(result.findings),
            "blocked_reason": result.blocked_reason,
            "report_path": output_paths["report"],
            "evidence_path": output_paths["evidence"],
            "sarif_path": str(sarif_path),
        }
        self.publisher.publish(run_summary)
        return run_summary

    @staticmethod
    def _new_run_id() -> str:
        now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{now}-{uuid.uuid4().hex[:8]}"
def _build_run_result_evidence(
    engagement_id: str,
    run_id: str,
    tool_name: str | None,
    tool_version: str | None,
    status: str,
    duration_ms: int,
    blocked_reason: str | None,
) -> Evidence:
    timestamp = datetime.now(timezone.utc).isoformat()
    data = {"blocked_reason": blocked_reason} if blocked_reason else {}
    return Evidence(
        id=f"run-{uuid.uuid4().hex[:8]}",
        timestamp=timestamp,
        type="run_result",
        target="run",
        data=data,
        schema_version=SCHEMA_VERSION,
        engagement_id=engagement_id,
        run_id=run_id,
        tool_name=tool_name,
        tool_version=tool_version,
        status=status,
        duration_ms=int(duration_ms),
    )
