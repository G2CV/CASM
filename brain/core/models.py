
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    """Evidence record captured during a run."""
    id: str
    timestamp: str
    type: str
    target: str
    data: dict[str, Any]
    target_id: str | None = None
    schema_version: str | None = None
    engagement_id: str | None = None
    run_id: str | None = None
    tool_name: str | None = None
    tool_version: str | None = None
    status: str | None = None
    duration_ms: int | None = None


@dataclass
class Finding:
    """Normalized finding for reporting and SARIF export."""
    id: str
    title: str
    severity: str
    target: str
    evidence_ids: list[str]
    summary: str
    timestamp: str


@dataclass
class ToolRequest:
    """Structured tool invocation payload used by adapters."""
    tool_name: str
    engagement_id: str
    run_id: str
    scope_snapshot: dict
    dry_run: bool
    per_attempt_timeout_ms: int
    tool_timeout_ms: int
    rate_limit: dict
    input: dict


@dataclass
class ToolResult:
    """Normalized tool response used by orchestration."""
    ok: bool
    blocked_reason: str | None
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    raw_redacted: dict | None = None
    tool_name: str | None = None
    tool_version: str | None = None
