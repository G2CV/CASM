from __future__ import annotations

from dataclasses import dataclass

from brain.core.diff import DiffFinding, DiffResult


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


@dataclass(frozen=True)
class AutoDiffSummary:
    added_count: int
    removed_count: int
    unchanged_count: int
    added_by_severity: dict[str, int]
    removed_by_severity: dict[str, int]
    top_added: list[DiffFinding]
    top_removed: list[DiffFinding]

    @property
    def has_changes(self) -> bool:
        return self.added_count > 0 or self.removed_count > 0


def build_auto_diff_summary(diff: DiffResult, max_findings: int = 20) -> AutoDiffSummary:
    """Build a stable, evidence-friendly summary from a SARIF diff."""
    max_findings = max(0, int(max_findings))
    ordered_added = _sorted_findings(diff.added)
    ordered_removed = _sorted_findings(diff.removed)
    return AutoDiffSummary(
        added_count=len(diff.added),
        removed_count=len(diff.removed),
        unchanged_count=len(diff.unchanged),
        added_by_severity=_count_by_severity(diff.added),
        removed_by_severity=_count_by_severity(diff.removed),
        top_added=ordered_added[:max_findings],
        top_removed=ordered_removed[:max_findings],
    )


def render_auto_diff_markdown(
    summary: AutoDiffSummary,
    *,
    old_label: str,
    new_label: str,
    run_url: str | None = None,
    evidence_path: str | None = None,
    sarif_path: str | None = None,
    report_path: str | None = None,
) -> str:
    """Render an evidence-first markdown block for GitHub comments/issues."""
    lines = [
        "## CASM Auto-Diff Report",
        "",
        f"- Baseline SARIF path (runner workspace): `{old_label}`",
        f"- Current SARIF: `{new_label}`",
        f"- Added findings: **{summary.added_count}**",
        f"- Removed findings: **{summary.removed_count}**",
        f"- Unchanged findings: {summary.unchanged_count}",
        f"- Added by severity: {_format_counts(summary.added_by_severity)}",
        f"- Removed by severity: {_format_counts(summary.removed_by_severity)}",
        "- Baseline persistence: GitHub Actions cache (unless you commit the baseline file).",
    ]
    if run_url:
        lines.append(f"- Workflow run: {run_url}")
    if evidence_path:
        lines.append(f"- Evidence JSONL: `{evidence_path}`")
    if sarif_path:
        lines.append(f"- SARIF: `{sarif_path}`")
    if report_path:
        lines.append(f"- Technical summary: `{report_path}`")

    if not summary.has_changes:
        lines.extend(
            [
                "",
                "### Result",
                "- No finding-level change detected against baseline.",
            ]
        )
        return "\n".join(lines)

    lines.extend(["", "### Added Findings"])
    if summary.top_added:
        lines.extend(_format_findings(summary.top_added))
    else:
        lines.append("- none")

    lines.extend(["", "### Removed Findings"])
    if summary.top_removed:
        lines.extend(_format_findings(summary.top_removed))
    else:
        lines.append("- none")

    return "\n".join(lines)


def render_bootstrap_markdown(
    *,
    new_label: str,
    run_url: str | None = None,
    evidence_path: str | None = None,
    sarif_path: str | None = None,
    report_path: str | None = None,
) -> str:
    """Render a first-run bootstrap report when no baseline SARIF exists."""
    lines = [
        "## CASM Auto-Diff Report",
        "",
        "- Baseline SARIF: _not found_",
        f"- Current SARIF: `{new_label}`",
        "- Baseline action: current SARIF has been promoted as the new baseline.",
        "- Baseline persistence: GitHub Actions cache (unless you commit the baseline file).",
    ]
    if run_url:
        lines.append(f"- Workflow run: {run_url}")
    if evidence_path:
        lines.append(f"- Evidence JSONL: `{evidence_path}`")
    if sarif_path:
        lines.append(f"- SARIF: `{sarif_path}`")
    if report_path:
        lines.append(f"- Technical summary: `{report_path}`")
    return "\n".join(lines)


def _sorted_findings(findings: list[DiffFinding]) -> list[DiffFinding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, SEVERITY_ORDER["unknown"]),
            item.rule_id,
            item.uri,
            item.fingerprint,
        ),
    )


def _count_by_severity(findings: list[DiffFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.severity if finding.severity else "unknown"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    ordered = sorted(
        counts.items(),
        key=lambda item: (SEVERITY_ORDER.get(item[0], SEVERITY_ORDER["unknown"]), item[0]),
    )
    return ", ".join(f"{name}:{value}" for name, value in ordered)


def _format_findings(findings: list[DiffFinding]) -> list[str]:
    rows: list[str] = []
    for finding in findings:
        header = f"[{finding.severity}] `{finding.rule_id}`"
        target = f" @ `{finding.uri}`" if finding.uri else ""
        rows.append(f"- {header}{target}")
        if finding.message:
            rows.append(f"  - {finding.message}")
    return rows
