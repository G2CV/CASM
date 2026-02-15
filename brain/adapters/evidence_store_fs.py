
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from brain.core.models import Evidence, Finding
from brain.core.schema_version import SCHEMA_VERSION
from brain.core.redaction import redact_data, redact_text


@dataclass
class FileSystemEvidenceStore:
    base_dir: str = "runs"

    def write(
        self,
        engagement_id: str,
        run_id: str,
        tool_name: str | None,
        tool_version: str | None,
        findings: list[Finding],
        evidence: list[Evidence],
        report_md: str,
        tool_stderr: str | None = None,
        tool_stdout: str | None = None,
    ) -> dict:
        """Persist run artifacts to the filesystem.

        Notes:
            Evidence and tool outputs are redacted before writing to reduce the
            risk of persisting secrets in run artifacts.
        """
        run_dir = Path(self.base_dir) / engagement_id / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = run_dir / "evidence.jsonl"
        report_path = run_dir / "report.md"
        stderr_path = None
        stdout_path = None

        if tool_stderr is not None:
            stderr_path = run_dir / "tool_stderr.log"
            stderr_path.write_text(redact_text(tool_stderr), encoding="utf-8")

        if tool_stdout is not None:
            stdout_path = run_dir / "tool_stdout.partial.log"
            stdout_path.write_text(redact_text(tool_stdout), encoding="utf-8")

        with evidence_path.open("w", encoding="utf-8") as handle:
            for item in evidence:
                payload = dict(item.__dict__)
                payload["engagement_id"] = engagement_id
                payload["run_id"] = run_id
                payload["tool_name"] = payload.get("tool_name") or tool_name
                payload["tool_version"] = payload.get("tool_version") or tool_version
                payload["schema_version"] = payload.get("schema_version") or SCHEMA_VERSION
                payload["status"] = payload.get("status") or "success"
                payload["duration_ms"] = int(payload.get("duration_ms") or 0)
                payload["data"] = redact_data(payload.get("data", {}))
                handle.write(json.dumps(payload, sort_keys=True) + "\n")

        report_path.write_text(report_md, encoding="utf-8")

        return {
            "evidence": str(evidence_path),
            "report": str(report_path),
            "tool_stderr": str(stderr_path) if stderr_path else None,
            "tool_stdout": str(stdout_path) if stdout_path else None,
        }
