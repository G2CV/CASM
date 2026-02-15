
from __future__ import annotations

from brain.core.models import Finding
from brain.core.schema_version import SCHEMA_VERSION


def build_sarif(
    findings: list[Finding],
    engagement_id: str,
    run_id: str,
    tool_name: str,
    tool_version: str,
) -> dict:
    """Build a SARIF report from findings.

    Args:
        findings (list[Finding]): Findings to export.
        engagement_id (str): Engagement identifier for metadata.
        run_id (str): Run identifier for metadata.
        tool_name (str): Tool name to record in SARIF properties.
        tool_version (str): Tool version for traceability.

    Returns:
        dict: SARIF v2.1.0 document.

    Notes:
        Fingerprints are stable across runs so diffing tools can track changes
        even when ordering or message formatting shifts slightly.
    """
    rules = []
    results = []
    seen_rules = set()

    for finding in findings:
        rule_id = _rule_id_for_finding(finding)
        if rule_id not in seen_rules:
            rules.append({"id": rule_id, "name": finding.title})
            seen_rules.add(rule_id)

        results.append(
            {
                "ruleId": rule_id,
                "level": _level_for_severity(finding.severity),
                "message": {
                    "text": f"{finding.summary} Recommendation: {_recommendation_for_finding(finding)}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"tcp://{finding.target}"}
                        }
                    }
                ],
                "properties": {
                    "engagement_id": engagement_id,
                    "run_id": run_id,
                    "evidence_ids": finding.evidence_ids,
                    "tool_name": tool_name,
                    "tool_version": tool_version,
                },
                "partialFingerprints": {
                    "primary": _fingerprint(tool_name, rule_id, finding.target),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CASM", "version": tool_version, "rules": rules}},
                "results": results,
                "properties": {"schema_version": SCHEMA_VERSION},
            }
        ],
        "properties": {"schema_version": SCHEMA_VERSION},
    }


def _fingerprint(tool_name: str, rule_id: str, target: str) -> str:
    import hashlib

    value = f"{tool_name}|{rule_id}|{target}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _rule_id_for_finding(finding: Finding) -> str:
    title = finding.title.lower()
    if "open tcp port" in title:
        return "OPEN_TCP_PORT"
    return "GENERIC_FINDING"


def _level_for_severity(severity: str) -> str:
    normalized = severity.lower()
    if normalized in {"high", "critical"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _recommendation_for_finding(finding: Finding) -> str:
    title = finding.title.lower()
    if "open tcp port" in title:
        return "Validate the service is required and restrict exposure where possible."
    return "Review configuration and apply least-privilege exposure."
