
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass


@dataclass
class DnsEnumGateway:
    tool_path: str
    timeout_ms: int = 30000

    def run(self, payload: dict) -> dict:
        """Execute the DNS enumeration tool and return raw JSON output.

        Notes:
            Parsing and report generation are handled in core so the adapter
            can stay focused on process execution and error mapping.
        """
        if os.environ.get("ABORT_RUN", "false").lower() == "true":
            return {"ok": False, "blocked_reason": "aborted"}
        if not os.path.exists(self.tool_path):
            return {"ok": False, "blocked_reason": "tool_not_found"}

        try:
            proc = subprocess.run(
                [self.tool_path],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=self.timeout_ms / 1000,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "blocked_reason": "tool_timeout"}

        if proc.returncode != 0:
            return {"ok": False, "blocked_reason": "tool_error"}

        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"ok": False, "blocked_reason": "invalid_tool_output"}
