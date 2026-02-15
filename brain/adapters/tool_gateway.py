
from __future__ import annotations

import json
import os
import subprocess
import time

from brain.core.models import Evidence, Finding, ToolRequest, ToolResult
from brain.core.scope import ScopeGuard


class ToolGatewayAdapter:
    """Run a tool that conforms to the standard ToolRequest/ToolResult contract.

    This adapter centralizes scope/rate enforcement so the tool never receives
    out-of-scope requests, keeping policy checks consistent across callers.
    """
    def __init__(self, tool_path: str, scope_guard: ScopeGuard, timeout_ms: int = 5000) -> None:
        self.tool_path = tool_path
        self.scope_guard = scope_guard
        self.timeout_ms = timeout_ms

    def run(self, request: ToolRequest) -> ToolResult:
        """Execute the tool and translate its JSON output into a ToolResult.

        Args:
            request (ToolRequest): Structured tool request containing scope snapshot,
                timing, and rate limit data.

        Returns:
            ToolResult: Parsed result with findings/evidence plus metrics and
                any blocked reason.

        Notes:
            This method does not raise subprocess errors; failures are converted
            into ToolResult.blocked_reason values to keep orchestration linear.
        """
        start = time.time()
        if os.environ.get("ABORT_RUN", "false").lower() == "true":
            return ToolResult(
                ok=False,
                blocked_reason="aborted",
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                tool_name=request.tool_name,
            )
        if request.dry_run:
            return ToolResult(
                ok=False,
                blocked_reason="dry_run",
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                tool_name=request.tool_name,
            )
        if not os.path.exists(self.tool_path):
            return ToolResult(
                ok=False,
                blocked_reason="tool_not_found",
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                tool_name=request.tool_name,
            )

        rate_decision = self.scope_guard.check_rate(
            float(request.rate_limit.get("rps", 1)),
            int(request.rate_limit.get("concurrency", 1)),
        )
        if not rate_decision.allowed:
            return ToolResult(
                ok=False,
                blocked_reason=rate_decision.reason,
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                tool_name=request.tool_name,
            )

        targets = request.input.get("targets", [])
        ports = request.input.get("ports", [])
        protocol = request.input.get("protocol", "tcp")
        for target in targets:
            host = target.get("host", "")
            for port in ports:
                decision = self.scope_guard.check_target(host, int(port), protocol)
                if not decision.allowed:
                    return ToolResult(
                        ok=False,
                        blocked_reason=decision.reason,
                        metrics={"duration_ms": int((time.time() - start) * 1000)},
                        tool_name=request.tool_name,
                    )

        payload = {
            "tool_name": request.tool_name,
            "engagement_id": request.engagement_id,
            "run_id": request.run_id,
            "scope": request.scope_snapshot,
            "dry_run": request.dry_run,
            "per_attempt_timeout_ms": request.per_attempt_timeout_ms,
            "tool_timeout_ms": request.tool_timeout_ms,
            "rate_limit": request.rate_limit,
            "input": request.input,
        }

        request_timeout = request.tool_timeout_ms if request.tool_timeout_ms > 0 else self.timeout_ms
        timeout_sec = request_timeout / 1000
        try:
            proc = subprocess.run(
                [self.tool_path],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or "")[-2000:]
            stdout = (exc.stdout or "")[-2000:]
            return ToolResult(
                ok=False,
                blocked_reason="tool_timeout",
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                raw_redacted={
                    "stderr": stderr,
                    "stdout": stdout,
                },
                tool_name=request.tool_name,
            )

        if proc.returncode != 0:
            stderr = proc.stderr[-2000:] if proc.stderr else ""
            stdout = proc.stdout[-2000:] if proc.stdout else ""
            return ToolResult(
                ok=False,
                blocked_reason="tool_error",
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                raw_redacted={
                    "stderr": stderr,
                    "stdout": stdout,
                },
                tool_name=request.tool_name,
            )

        try:
            raw = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ToolResult(
                ok=False,
                blocked_reason="invalid_tool_output",
                metrics={"duration_ms": int((time.time() - start) * 1000)},
                tool_name=request.tool_name,
            )

        findings = [Finding(**item) for item in raw.get("findings", [])]
        evidence = [Evidence(**item) for item in raw.get("evidence", [])]
        raw_redacted = raw.get("raw_redacted") or {}
        if proc.stderr:
            raw_redacted["stderr"] = proc.stderr[-2000:]
        if proc.stdout:
            raw_redacted["stdout"] = proc.stdout[-2000:]
        return ToolResult(
            ok=bool(raw.get("ok", False)),
            blocked_reason=raw.get("blocked_reason"),
            findings=findings,
            evidence=evidence,
            metrics={**raw.get("metrics", {}), "duration_ms": int((time.time() - start) * 1000)},
            raw_redacted=raw_redacted,
            tool_name=raw.get("tool_name"),
            tool_version=raw.get("tool_version"),
        )
