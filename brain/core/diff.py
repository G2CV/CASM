
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiffFinding:
    fingerprint: str
    rule_id: str
    severity: str
    uri: str
    message: str


@dataclass
class DiffResult:
    added: list[DiffFinding]
    removed: list[DiffFinding]
    unchanged: list[DiffFinding]


def diff_sarif(old_path: str, new_path: str, tool_filter: str | None = "http_verify") -> DiffResult:
    """Compute a stable diff between two SARIF files.

    Args:
        old_path (str): Path to the baseline SARIF file.
        new_path (str): Path to the current SARIF file.
        tool_filter (str | None): Optional tool suffix filter for run IDs.

    Returns:
        DiffResult: Added/removed/unchanged findings based on fingerprints.

    Notes:
        Fingerprints are used so the diff stays stable even when ordering or
        incidental SARIF metadata changes between runs.
    """
    old_findings = _load_sarif_findings(old_path, tool_filter)
    new_findings = _load_sarif_findings(new_path, tool_filter)

    old_map = {item.fingerprint: item for item in old_findings}
    new_map = {item.fingerprint: item for item in new_findings}

    added = [new_map[key] for key in new_map.keys() - old_map.keys()]
    removed = [old_map[key] for key in old_map.keys() - new_map.keys()]
    unchanged = [new_map[key] for key in new_map.keys() & old_map.keys()]

    return DiffResult(
        added=_sorted_findings(added),
        removed=_sorted_findings(removed),
        unchanged=_sorted_findings(unchanged),
    )


def render_diff_report(
    diff: DiffResult,
    old_label: str,
    new_label: str,
    include_unchanged: bool = False,
) -> str:
    """Render a human-readable diff summary.

    Args:
        diff (DiffResult): Diff data to render.
        old_label (str): Label for the baseline SARIF.
        new_label (str): Label for the comparison SARIF.
        include_unchanged (bool): Whether to include unchanged findings.

    Returns:
        str: Markdown report for CLI or file output.
    """
    lines = [
        "# CASM Diff Report",
        "",
        f"Old: {old_label}",
        f"New: {new_label}",
        "",
        "## Summary",
        f"- Added: {len(diff.added)}",
        f"- Removed: {len(diff.removed)}",
        f"- Unchanged: {len(diff.unchanged)}",
        "",
        "## Added",
    ]

    if diff.added:
        lines.extend(_format_findings(diff.added))
    else:
        lines.append("- none")

    lines.extend(["", "## Removed"])
    if diff.removed:
        lines.extend(_format_findings(diff.removed))
    else:
        lines.append("- none")

    if include_unchanged:
        lines.extend(["", "## Unchanged"])
        if diff.unchanged:
            lines.extend(_format_findings(diff.unchanged))
        else:
            lines.append("- none")

    return "\n".join(lines)


def _load_sarif_findings(path: str, tool_filter: str | None) -> list[DiffFinding]:
    """Load findings from SARIF, applying optional tool filtering.

    Notes:
        The fingerprint selection prefers tool-provided IDs, falling back to a
        deterministic hash to avoid noisy diffs when tools omit fingerprints.
    """
    sarif = json.loads(Path(path).read_text(encoding="utf-8"))
    runs = sarif.get("runs", []) if isinstance(sarif, dict) else []
    findings: list[DiffFinding] = []

    for run in runs:
        if not isinstance(run, dict):
            continue
        if tool_filter and not _run_matches(run, tool_filter):
            continue
        results = run.get("results") or []
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            location = result.get("locations", [{}])[0]
            uri = (
                location.get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
            severity = _severity_from_result(props, result.get("level"))
            fingerprint = _fingerprint_from_result(result, rule_id, uri, message)
            findings.append(
                DiffFinding(
                    fingerprint=fingerprint,
                    rule_id=rule_id,
                    severity=severity,
                    uri=uri,
                    message=message,
                )
            )

    return findings


def _severity_from_result(properties: dict, level: str | None) -> str:
    severity = properties.get("severity")
    if isinstance(severity, str) and severity:
        return severity
    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    if level == "note":
        return "low"
    return "unknown"


def _fingerprint_from_result(result: dict, rule_id: str, uri: str, message: str) -> str:
    props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
    fingerprint = props.get("finding_fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        return fingerprint
    partial = result.get("partialFingerprints", {})
    if isinstance(partial, dict):
        primary = partial.get("primary")
        if isinstance(primary, str) and primary:
            return primary
    value = f"{rule_id}|{uri}|{message}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _run_matches(run: dict, tool_filter: str) -> bool:
    automation = run.get("runAutomationDetails", {})
    if isinstance(automation, dict):
        run_id = automation.get("id", "")
        if isinstance(run_id, str) and run_id:
            return run_id.endswith(f":{tool_filter}")
    return True


def _sorted_findings(findings: list[DiffFinding]) -> list[DiffFinding]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        findings,
        key=lambda item: (severity_order.get(item.severity, 9), item.rule_id, item.uri),
    )


def _format_findings(findings: list[DiffFinding]) -> list[str]:
    lines = []
    for item in findings:
        detail = f"{item.rule_id} @ {item.uri}" if item.uri else item.rule_id
        prefix = item.severity or "unknown"
        lines.append(f"- {prefix}: {detail}")
    return lines
