
from __future__ import annotations

from collections import Counter

from brain.core.models import Evidence, Finding
from brain.core.schema_version import SCHEMA_VERSION
from brain.core.scope import Scope
from brain.core.version import get_casm_version


def render_report(
    scope: Scope,
    run_id: str,
    findings: list[Finding],
    evidence: list[Evidence],
    blocked_reason: str | None,
    dry_run: bool,
) -> str:
    """Render a run report suitable for sharing with stakeholders.

    Args:
        scope (Scope): Scope metadata used for the report context.
        run_id (str): Run identifier for traceability.
        findings (list[Finding]): Findings to summarize.
        evidence (list[Evidence]): Evidence events from the run.
        blocked_reason (str | None): Optional block reason for the run.
        dry_run (bool): Whether the run was policy-only.

    Returns:
        str: Markdown report content.

    Notes:
        Risk is derived from the highest observed severity to keep the summary
        conservative and easy to interpret.
    """
    counts = Counter(f.severity for f in findings)
    endpoints = [item for item in evidence if item.type == "tcp_connect"]
    host_count = len({ _extract_host(item.target) for item in endpoints })
    endpoint_count = len(endpoints)
    success_count = sum(1 for item in endpoints if item.status == "success")
    timeout_count = sum(1 for item in endpoints if item.status == "timeout")
    overall_risk = _derive_overall_risk(counts)
    recommendations = _derive_recommendations(findings, overall_risk)
    lines = [
        "# CASM Report",
        "## Continuous Attack Surface Monitoring",
        "",
        f"CASM version: {get_casm_version()}",
        f"Report schema: {SCHEMA_VERSION}",
        "",
        f"Engagement: {scope.engagement_id}",
        f"Run: {run_id}",
    ]

    if blocked_reason:
        lines.extend(["", f"Status: blocked ({blocked_reason})"])

    lines.extend(
        [
            "",
            "## Executive Summary",
            f"- Overall risk is {overall_risk}.",
            "- Overall risk is based on the highest severity observed.",
            f"- Hosts assessed: {host_count}.",
            f"- Endpoints attempted: {endpoint_count}.",
            f"- Endpoints confirmed open: {success_count}.",
            f"- Endpoints timed out: {timeout_count}.",
        ]
    )

    for rec in recommendations:
        lines.append(f"- Recommendation: {rec}")

    lines.extend(
        [
            "",
            "## Technical Summary",
            f"Findings: {len(findings)}",
            "By severity:",
        ]
    )

    if counts:
        for severity, count in _ordered_counts(counts, ["critical", "high", "medium", "low", "info", "unknown"]):
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Scope & Method",
            f"Seed targets: {', '.join(scope.seed_targets) if scope.seed_targets else 'none'}",
            f"Allowed ports: {', '.join(str(p) for p in scope.allowed_ports) if scope.allowed_ports else 'none'}",
            f"Allowed protocols: {', '.join(scope.allowed_protocols) if scope.allowed_protocols else 'none'}",
            f"Max rate: {scope.max_rate}",
            f"Max concurrency: {scope.max_concurrency}",
            f"Per-attempt timeout (ms): {scope.per_attempt_timeout_ms}",
            f"Tool timeout (ms): {scope.tool_timeout_ms}",
            f"DRY_RUN: {str(dry_run).lower()}",
        ]
    )

    lines.extend(["", "## Limitations"])
    limitations = [
        "TCP connect only; no banner/service fingerprinting.",
        "Timeouts may indicate filtering or rate limiting, not necessarily closed ports.",
    ]
    if not scope.auth_allowed:
        limitations.append("No authenticated testing performed.")
    for item in limitations[:3]:
        lines.append(f"- {item}")

    if endpoints:
        lines.extend(["", "## Assets Observed", "Host | Open ports | Timed-out ports", "---|---|---"])
        for host in sorted({_extract_host(item.target) for item in endpoints}):
            open_ports = sorted(
                _extract_port(item.target)
                for item in endpoints
                if _extract_host(item.target) == host and item.status == "success"
            )
            timeout_ports = sorted(
                _extract_port(item.target)
                for item in endpoints
                if _extract_host(item.target) == host and item.status == "timeout"
            )
            open_str = ", ".join(str(p) for p in open_ports) if open_ports else "-"
            timeout_str = ", ".join(str(p) for p in timeout_ports) if timeout_ports else "-"
            lines.append(f"{host} | {open_str} | {timeout_str}")

    lines.extend(["", "## Findings"])

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    for finding in findings:
        lines.extend(
            [
                "",
                f"### {finding.title}",
                f"Severity: {finding.severity}",
                f"Target: {finding.target}",
                f"Summary: {finding.summary}",
                f"Evidence: {', '.join(finding.evidence_ids)}",
                f"Recommendation: {_recommendation_for_finding(finding)}",
            ]
        )

    if evidence:
        attempt_evidence = [item for item in evidence if item.type == "tcp_connect"]
        status_counts = Counter(item.status or "unknown" for item in attempt_evidence)
        lines.extend(
            [
                "",
                "## Scan Telemetry",
                f"Endpoints attempted: {len(attempt_evidence)}",
                f"Endpoints confirmed open: {sum(1 for item in attempt_evidence if item.status == 'success')}",
                f"Endpoints timed out: {sum(1 for item in attempt_evidence if item.status == 'timeout')}",
                "By status:",
            ]
        )
        if status_counts:
            for status, count in _ordered_counts(status_counts, ["success", "timeout", "error", "blocked", "unknown"]):
                lines.append(f"- {status}: {count}")
        else:
            lines.append("- none")

    return "\n".join(lines)


def _derive_overall_risk(counts: Counter) -> str:
    if counts.get("critical") or counts.get("high"):
        return "high"
    if counts.get("medium"):
        return "moderate"
    if counts.get("low"):
        return "low"
    return "minimal"


def _derive_recommendations(findings: list[Finding], overall_risk: str) -> list[str]:
    recs = []
    if any(f.title.lower().startswith("open tcp port") for f in findings):
        recs.append("Review exposed services and close any that are not required.")
    if overall_risk in {"high", "moderate"}:
        recs.append("Prioritize remediation for the highest-severity items.")
    if not recs:
        recs.append("Continue monitoring and re-scan after changes.")
    return recs[:3]


def _recommendation_for_finding(finding: Finding) -> str:
    title = finding.title.lower()
    if "open tcp port" in title:
        return "Validate the service is required and restrict exposure where possible."
    return "Review configuration and apply least-privilege exposure."


def _ordered_counts(counter: Counter, order: list[str]) -> list[tuple[str, int]]:
    remaining = {key: counter[key] for key in counter.keys() if key not in order}
    items = [(key, counter[key]) for key in order if key in counter]
    items.extend(sorted(remaining.items()))
    return items


def _extract_host(target: str) -> str:
    if ":" in target:
        return target.split(":", 1)[0]
    return target


def _extract_port(target: str) -> int:
    if ":" in target:
        try:
            return int(target.split(":", 1)[1])
        except ValueError:
            return 0
    return 0
