
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from brain.adapters.http_verify_gateway import HttpVerifyGateway
from brain.adapters.tool_gateway import ToolGatewayAdapter
from brain.core.http_verify import build_http_targets, build_http_verify_request
from brain.core.inventory import TargetRecord, write_inventory
from brain.core.models import Evidence, Finding, ToolRequest, ToolResult
from brain.core.sarif import build_sarif
from brain.core.scope import Scope, ScopeGuard
from brain.core.schema_version import SCHEMA_VERSION
from brain.core.url_canonical import canonicalize_url
from brain.core.dns_enum import execute_dns_enum


@dataclass
class UnifiedOutputs:
    targets_path: str
    evidence_path: str
    report_path: str
    sarif_path: str
    sarif_probe_path: str | None = None
    sarif_http_path: str | None = None
    sarif_dns_path: str | None = None


@dataclass
class ImportSummary:
    source_path: str
    total_targets: int
    deduped_targets: int
    allowed_targets: int
    blocked_targets: int
    attempted_targets: int
    skipped_targets: int


def run_unified(
    scope_path: str,
    out_dir: str,
    sarif_mode: str,
    probe_tool_path: str,
    http_tool_path: str,
    dry_run: bool,
    targets_file: str | None = None,
    detailed_report: bool = False,
    dns_tool_path: str | None = None,
    dns_enabled: bool | None = None,
    dns_wordlist: str | None = None,
) -> UnifiedOutputs:
    """Run probe + optional DNS + HTTP verify and merge artifacts.

    Args:
        scope_path (str): Scope configuration path.
        out_dir (str): Output directory for merged artifacts.
        sarif_mode (str): SARIF output strategy (merged or per-tool).
        probe_tool_path (str): Path to the probe binary.
        http_tool_path (str): Path to the http-verify binary.
        dry_run (bool): If True, tools should avoid network I/O.
        targets_file (str | None): Optional prebuilt targets list to skip probe.
        detailed_report (bool): Include verbose sections in the report.
        dns_tool_path (str | None): Path to DNS enum tool (if enabled).
        dns_enabled (bool | None): Force DNS enum on/off regardless of scope.
        dns_wordlist (str | None): Override DNS wordlist for active discovery.

    Returns:
        UnifiedOutputs: Paths to merged evidence, SARIF, and report artifacts.

    Notes:
        DNS discovery can expand HTTP targets; those are normalized/deduped
        before verification to keep the HTTP phase bounded.
    """
    scope = Scope.from_file(scope_path)
    run_id = _new_run_id()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    dns_events: list[dict] = []
    dns_discoveries: list[dict] = []
    dns_wildcards: list[dict] = []
    dns_sarif: dict | None = None
    dns_enabled_effective = (
        dns_enabled
        if dns_enabled is not None
        else bool((scope.dns_enumeration or {}).get("enabled", False))
    )
    if dns_enabled_effective:
        if dns_tool_path is None:
            dns_tool_path = "hands/bin/dns_enum"
        overrides: dict | None = None
        if dns_wordlist:
            overrides = {
                "wordlist_path": dns_wordlist,
                "active_discovery": {"wordlist": dns_wordlist},
            }
        dns_domains = _dns_domains_from_scope(scope)
        if dns_domains:
            dns_outputs = execute_dns_enum(
                scope=scope,
                run_id=run_id,
                domains=dns_domains,
                tool_path=dns_tool_path,
                dry_run=dry_run,
                overrides=overrides,
            )
            dns_events = dns_outputs.events
            dns_discoveries = dns_outputs.discoveries
            dns_wildcards = dns_outputs.wildcards
            dns_sarif = dns_outputs.sarif

    import_summary = None
    expected_http_targets = None
    if targets_file:
        raw_targets = load_targets_file(targets_file)
        normalized_targets = normalize_targets(raw_targets)
        inventory, http_targets, import_summary = build_import_inventory(
            scope,
            normalized_targets,
            targets_file,
            total_targets=len(raw_targets),
        )
        if dns_discoveries:
            dns_http_targets = build_http_targets(scope, _dns_hosts_from_discoveries(dns_discoveries))
            http_targets = normalize_targets(http_targets + dns_http_targets)
        expected_http_targets = len(http_targets)
        probe_result = ToolResult(
            ok=True,
            blocked_reason=None,
            findings=[],
            evidence=[],
            tool_name="probe",
            tool_version="dev",
        )
    else:
        probe_request = _probe_request(scope, run_id, dry_run)
        probe_gateway = ToolGatewayAdapter(tool_path=probe_tool_path, scope_guard=ScopeGuard(scope))
        probe_result = probe_gateway.run(probe_request)

        http_targets = derive_http_targets(scope, probe_result)
        if dns_discoveries:
            dns_http_targets = build_http_targets(scope, _dns_hosts_from_discoveries(dns_discoveries))
            http_targets = normalize_targets(http_targets + dns_http_targets)
        expected_http_targets = len(http_targets)
        inventory = build_unified_inventory(scope, http_targets)

    http_request = build_http_verify_request(scope, run_id, dry_run, str(out))
    http_request.payload["targets"] = http_targets
    http_request.payload["https_ports"] = scope.http_verify_https_ports
    http_gateway = HttpVerifyGateway(
        tool_path=http_tool_path,
        timeout_ms=_estimate_http_timeout_ms(scope, http_targets),
    )
    http_result = http_gateway.run(http_request.payload)

    targets_path = write_inventory(str(out / "targets.jsonl"), inventory)

    evidence_path = str(out / "evidence.jsonl")
    unified_evidence = merge_evidence(
        scope,
        run_id,
        probe_result,
        http_request.evidence_path,
        http_result,
        dns_events=dns_events,
    )
    write_evidence(evidence_path, unified_evidence)

    sarif_path, sarif_probe_path, sarif_http_path, sarif_dns_path = write_unified_sarif(
        out,
        scope,
        run_id,
        sarif_mode,
        probe_result,
        http_request.sarif_path,
        dns_sarif,
    )

    report_path = str(out / "report.md")
    report_md = render_unified_report(
        scope,
        run_id,
        probe_result,
        http_request.sarif_path,
        unified_evidence,
        import_summary=import_summary,
        expected_http_targets=expected_http_targets,
        detailed_report=detailed_report,
    )
    Path(report_path).write_text(report_md, encoding="utf-8")

    return UnifiedOutputs(
        targets_path=targets_path,
        evidence_path=evidence_path,
        report_path=report_path,
        sarif_path=sarif_path,
        sarif_probe_path=sarif_probe_path,
        sarif_http_path=sarif_http_path,
        sarif_dns_path=sarif_dns_path,
    )


def derive_http_targets(scope: Scope, probe_result: ToolResult) -> list[dict]:
    """Derive HTTP targets from probe findings within scope.

    Args:
        scope (Scope): Scope controls for protocol and HTTPS port overrides.
        probe_result (ToolResult): Results containing host:port findings.

    Returns:
        list[dict]: Canonicalized HTTP targets suitable for http-verify.

    Notes:
        Findings are filtered through ScopeGuard again to prevent a probe bug
        from expanding into out-of-scope verification.
    """
    http_targets: dict[str, dict] = {}
    guard = ScopeGuard(scope)
    for finding in probe_result.findings:
        host, port = _split_host_port(finding.target)
        if not host or port is None:
            continue
        if not guard.check_target(host, port, "tcp").allowed:
            continue
        if port in scope.http_verify_https_ports:
            url = f"https://{host}:{port}/"
            http_targets[f"HEAD {url}"] = {"url": url, "method": "HEAD"}
            continue
        for protocol in scope.allowed_protocols:
            if protocol not in {"http", "https"}:
                continue
            url = f"{protocol}://{host}:{port}/"
            http_targets[f"HEAD {url}"] = {"url": url, "method": "HEAD"}

    return _sorted_targets(http_targets.values())


def load_targets_file(path: str) -> list[dict]:
    """Load a JSON targets file and validate structure for imports.

    Args:
        path (str): Path to a JSON object with a "targets" array.

    Returns:
        list[dict]: Raw targets with "url" and optional "method".

    Raises:
        ValueError: If the file structure is invalid or entries are malformed.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Targets file must be a JSON object with 'targets'")
    targets = data.get("targets")
    if not isinstance(targets, list):
        raise ValueError("Targets file must include a 'targets' array")
    parsed_targets = []
    for index, item in enumerate(targets):
        if not isinstance(item, dict):
            raise ValueError(f"Target entry at index {index} must be an object")
        url = item.get("url")
        if not url:
            raise ValueError(f"Target entry at index {index} missing url")
        method = item.get("method", "HEAD")
        parsed_targets.append({"url": url, "method": method})
    return parsed_targets


def normalize_targets(targets: Iterable[dict]) -> list[dict]:
    """Normalize and dedupe targets to keep verification deterministic.

    Args:
        targets (Iterable[dict]): Target objects with "url" and "method" keys.

    Returns:
        list[dict]: Deduped, normalized targets sorted for stable output.

    Notes:
        Method + canonical URL form the uniqueness key so retries are stable
        across re-runs and imported inputs.
    """
    seen: dict[str, dict] = {}
    for item in targets:
        url = str(item.get("url", "")).strip()
        method = str(item.get("method", "HEAD"))
        normalized_url = _normalize_url(url)
        normalized_method = _normalize_method(method)
        key = f"{normalized_method} {normalized_url}"
        seen[key] = {"url": normalized_url, "method": normalized_method}
    return _sorted_targets(seen.values())


def build_import_inventory(
    scope: Scope,
    targets: list[dict],
    source_path: str,
    total_targets: int,
) -> tuple[list[TargetRecord], list[dict], ImportSummary]:
    """Build inventory records for imported HTTP targets.

    Args:
        scope (Scope): Scope controls used for allow/deny decisions.
        targets (list[dict]): Normalized targets with "url" and "method".
        source_path (str): Source file path for traceability.
        total_targets (int): Count of raw targets prior to dedupe.

    Returns:
        tuple[list[TargetRecord], list[dict], ImportSummary]: Inventory records,
        allowed targets, and an import summary for reporting.

    Notes:
        This preserves blocked targets for auditability while only allowing
        in-scope targets to flow into verification.
    """
    guard = ScopeGuard(scope)
    records: list[TargetRecord] = []
    allowed_targets: list[dict] = []
    for target in targets:
        parsed_host, parsed_port = _split_host_port_from_url(target["url"])
        protocol = _scheme(target["url"])
        decision = guard.check_target(parsed_host, parsed_port, protocol)
        records.append(
            TargetRecord(
                target=target["url"],
                protocol=protocol,
                host=parsed_host,
                port=parsed_port,
                resolved_ip=None,
                allowed=decision.allowed,
                reason=decision.reason,
                source="import",
                source_path=source_path,
            )
        )
        if decision.allowed:
            allowed_targets.append(target)

    blocked_targets = len(targets) - len(allowed_targets)
    summary = ImportSummary(
        source_path=source_path,
        total_targets=total_targets,
        deduped_targets=len(targets),
        allowed_targets=len(allowed_targets),
        blocked_targets=blocked_targets,
        attempted_targets=len(allowed_targets),
        skipped_targets=blocked_targets,
    )
    return records, allowed_targets, summary


def build_unified_inventory(scope: Scope, http_targets: list[dict]) -> list[TargetRecord]:
    guard = ScopeGuard(scope)
    records: list[TargetRecord] = []

    for host in scope.seed_targets:
        for port in scope.allowed_ports:
            decision = guard.check_target(host, port, "tcp")
            records.append(
                TargetRecord(
                    target=f"{host}:{port}",
                    protocol="tcp",
                    host=host,
                    port=port,
                    resolved_ip=None,
                    allowed=decision.allowed,
                    reason=decision.reason,
                    source="seed",
                    source_path=None,
                )
            )

    for target in http_targets:
        parsed_host, parsed_port = _split_host_port_from_url(target["url"])
        decision = guard.check_target(parsed_host, parsed_port, _scheme(target["url"]))
        records.append(
            TargetRecord(
                target=target["url"],
                protocol=_scheme(target["url"]),
                host=parsed_host,
                port=parsed_port,
                resolved_ip=None,
                allowed=decision.allowed,
                reason=decision.reason,
                source="probe_open_port",
                source_path=None,
            )
        )

    return sorted(records, key=lambda item: (item.protocol, item.host, item.port, item.target))


def merge_evidence(
    scope: Scope,
    run_id: str,
    probe_result: ToolResult,
    http_evidence_path: str,
    http_result: dict,
    dns_events: list[dict] | None = None,
) -> list[dict]:
    events: list[dict] = []
    if dns_events:
        events.extend(dns_events)
    for item in probe_result.evidence:
        payload = dict(item.__dict__)
        payload["engagement_id"] = scope.engagement_id
        payload["run_id"] = run_id
        payload["tool_name"] = probe_result.tool_name or "probe"
        payload["tool_version"] = probe_result.tool_version
        target_url = f"tcp://{item.target}"
        payload["target_id"] = _target_id("tcp", target_url)
        payload["attempt_id"] = _attempt_id(payload["target_id"], item.id)
        events.append(payload)

    if Path(http_evidence_path).exists():
        http_events = []
        with Path(http_evidence_path).open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                data = event.get("data", {}) if isinstance(event.get("data", {}), dict) else {}
                if event.get("type") in {"http_attempt", "http_response"}:
                    canonical_target = data.get("final_url") or data.get("url")
                    if canonical_target and "canonical_url" not in data:
                        data["canonical_url"] = canonicalize_url(str(canonical_target))
                    if "redirect_chain" in data and "canonical_redirect_chain" not in data:
                        chain = data.get("redirect_chain")
                        if isinstance(chain, list):
                            data["canonical_redirect_chain"] = [
                                canonicalize_url(str(item)) for item in chain
                            ]
                    event["data"] = data
                if "schema_version" not in event:
                    event["schema_version"] = SCHEMA_VERSION
                url = event.get("data", {}).get("url", "")
                method = event.get("data", {}).get("method", "HEAD")
                target_id = _target_id(method, url)
                event["target_id"] = target_id
                http_events.append(event)

        http_events = _sorted_events(http_events)
        attempt_map: dict[str, str] = {}
        for event in http_events:
            data = event.get("data", {})
            url = data.get("url", "")
            method = data.get("method", "HEAD")
            key = f"{method}:{url}"
            if event.get("type") == "http_attempt":
                attempt_id = _attempt_id(event.get("target_id", ""), event.get("id", ""))
                attempt_map[key] = attempt_id
                event["attempt_id"] = attempt_id
            else:
                event["attempt_id"] = attempt_map.get(key, _attempt_id(event.get("target_id", ""), event.get("id", "")))
            events.append(event)

    return _sorted_events(events)


def write_evidence(path: str, events: list[dict]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def write_unified_sarif(
    out: Path,
    scope: Scope,
    run_id: str,
    sarif_mode: str,
    probe_result: ToolResult,
    http_sarif_path: str,
    dns_sarif: dict | None = None,
) -> tuple[str, str | None, str | None, str | None]:
    probe_sarif = build_sarif(
        probe_result.findings,
        scope.engagement_id,
        run_id,
        probe_result.tool_name or "probe",
        probe_result.tool_version or "dev",
    )
    _set_run_automation(probe_sarif, scope.engagement_id, run_id, "probe")

    http_sarif = {}
    if Path(http_sarif_path).exists():
        http_sarif = json.loads(Path(http_sarif_path).read_text(encoding="utf-8"))
        _set_run_automation(http_sarif, scope.engagement_id, run_id, "http_verify")
        _normalize_sarif_runs(http_sarif)

    if dns_sarif:
        _set_run_automation(dns_sarif, scope.engagement_id, run_id, "dns_enum")
        _normalize_sarif_runs(dns_sarif)

    if sarif_mode == "github":
        probe_path = out / "results-probe.sarif"
        probe_path.write_text(json.dumps(probe_sarif, indent=2, sort_keys=True), encoding="utf-8")
        http_path = out / "results-http-verify.sarif"
        http_path.write_text(json.dumps(http_sarif, indent=2, sort_keys=True), encoding="utf-8")
        dns_path = None
        if dns_sarif:
            dns_path_obj = out / "results-dns-enum.sarif"
            dns_path_obj.write_text(json.dumps(dns_sarif, indent=2, sort_keys=True), encoding="utf-8")
            dns_path = str(dns_path_obj)
        return str(probe_path), str(probe_path), str(http_path), dns_path

    combined = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": probe_sarif.get("runs", [])
        + http_sarif.get("runs", [])
        + (dns_sarif.get("runs", []) if dns_sarif else []),
        "properties": {"schema_version": SCHEMA_VERSION},
    }
    combined_path = out / "results.sarif"
    combined_path.write_text(json.dumps(combined, indent=2, sort_keys=True), encoding="utf-8")
    return str(combined_path), None, None, None


def render_unified_report(
    scope: Scope,
    run_id: str,
    probe_result: ToolResult,
    http_sarif_path: str,
    evidence: list[dict],
    import_summary: ImportSummary | None = None,
    expected_http_targets: int | None = None,
    detailed_report: bool = False,
) -> str:
    http_findings = []
    if Path(http_sarif_path).exists():
        sarif = json.loads(Path(http_sarif_path).read_text(encoding="utf-8"))
        for run in sarif.get("runs", []):
            run_id_value = run.get("runAutomationDetails", {}).get("id", "")
            if run_id_value and not run_id_value.endswith(":http_verify"):
                continue
            for result in run.get("results") or []:
                http_findings.append(result)

    aggregates = _aggregate_http_findings(http_findings, evidence)

    http_attempts = sum(1 for item in evidence if item.get("type") == "http_attempt")
    http_responses = sum(1 for item in evidence if item.get("type") == "http_response")
    http_errors = sum(1 for item in evidence if item.get("type") == "http_error")
    http_blocked = sum(1 for item in evidence if item.get("type") == "http_blocked")
    dns_discoveries = [item for item in evidence if item.get("type") == "dns_discovery"]
    dns_wildcards = [item for item in evidence if item.get("type") == "dns_wildcard_detected"]

    lines = [
        "# CASM Unified Report",
        "## Continuous Attack Surface Monitoring",
        "",
        f"Report schema: {SCHEMA_VERSION}",
        "",
        f"Engagement: {scope.engagement_id}",
        f"Run: {run_id}",
        "",
        "## Executive Summary",
        f"- Open ports found: {len(probe_result.findings)}.",
        f"- DNS subdomains discovered: {len(dns_discoveries)}.",
        f"- HTTP findings: {len(http_findings)}.",
        f"- HTTP attempts observed: {http_attempts}.",
        f"- HTTP responses observed: {http_responses}.",
        f"- HTTP errors observed: {http_errors}.",
        f"- HTTP blocked observed: {http_blocked}.",
        "",
        "## Scope & Method",
        f"Seed targets: {', '.join(scope.seed_targets)}",
        f"Allowed ports: {', '.join(str(p) for p in scope.allowed_ports)}",
        f"Allowed protocols: {', '.join(scope.allowed_protocols)}",
        "",
        "## DNS Enumeration Results",
    ]

    if dns_discoveries:
        lines.append(f"Discovered subdomains: {len(dns_discoveries)}")
        for item in dns_discoveries[:15]:
            data = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
            subdomain = data.get("subdomain") or item.get("target")
            record_type = data.get("record_type") or ""
            values = data.get("values") if isinstance(data.get("values"), list) else []
            value_str = ", ".join(values) if values else "-"
            lines.append(f"- {subdomain} -> {record_type} {value_str}")
    else:
        lines.append("No DNS discoveries.")

    if dns_wildcards:
        lines.append("Wildcard DNS detected:")
        for item in dns_wildcards[:5]:
            data = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
            domain = data.get("domain") or item.get("target")
            values = data.get("values") if isinstance(data.get("values"), list) else []
            value_str = ", ".join(values) if values else "-"
            lines.append(f"- {domain} -> {value_str}")

    lines.append("")
    lines.append("## Findings (probe)")

    if import_summary:
        lines[lines.index("## Scope & Method") + 1 : lines.index("## Scope & Method") + 1] = [
            "Method: Imported targets file",
            f"Targets file: {import_summary.source_path}",
            f"Imported targets: {import_summary.total_targets}",
            f"Deduped targets: {import_summary.deduped_targets}",
            f"Allowed targets: {import_summary.allowed_targets}",
            f"Blocked targets: {import_summary.blocked_targets}",
            f"Attempted targets: {import_summary.attempted_targets}",
            f"Skipped targets: {import_summary.skipped_targets}",
        ]

    if not probe_result.findings:
        lines.append("No probe findings.")
    for finding in probe_result.findings:
        lines.extend(
            [
                "",
                f"### {finding.title}",
                f"Severity: {finding.severity}",
                f"Target: {finding.target}",
                f"Summary: {finding.summary}",
            ]
        )

    lines.extend(["", "## Findings (http_verify)"])
    if not http_findings:
        if http_responses or http_attempts:
            lines.append("No http_verify findings emitted by the tool.")
        else:
            lines.append("No http_verify findings.")
    if aggregates:
        for entry in aggregates:
            lines.extend(
                [
                    "",
                    f"### {entry['rule_id']} ({entry['count']} endpoints affected) — {entry['severity']}",
                    entry["summary"],
                    f"First detected: {entry['first_seen']}",
                    f"Last detected: {entry['last_seen']}",
                    "Affected endpoints:",
                    *[f"- {value}" for value in entry["endpoints"]],
                ]
            )
            if entry["more_endpoints"]:
                lines.append(f"- ... and {entry['more_endpoints']} others")
            if entry["evidence_ids"]:
                lines.append(f"Evidence: {', '.join(entry['evidence_ids'])}")

    if detailed_report and http_findings:
        lines.extend(["", "## Findings (http_verify, detailed)"])
        for result in http_findings:
            message = result.get("message", {}).get("text", "")
            rule_id = result.get("ruleId", "")
            location = result.get("locations", [{}])[0]
            uri = (
                location.get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            lines.extend(["", f"### {rule_id}", f"Target: {uri}", f"Summary: {message}"])

    if expected_http_targets is not None and http_attempts < expected_http_targets:
        lines.append(
            "Warning: http_verify completed fewer targets than scheduled; check tool timeout or errors."
        )

    lines.extend(["", "## Scan Telemetry", f"Events: {len(evidence)}"])
    return "\n".join(lines)


def _aggregate_http_findings(http_findings: list[dict], evidence: list[dict]) -> list[dict]:
    if not http_findings:
        return []

    fingerprint_index: dict[str, dict[str, object]] = {}
    for event in evidence:
        if event.get("type") != "http_response":
            continue
        timestamp = event.get("timestamp")
        event_id = event.get("id")
        raw_data = event.get("data")
        data: dict[str, object]
        if isinstance(raw_data, dict):
            data = raw_data
        else:
            data = {}
        fingerprints: list[str] = []
        if "finding_fingerprint" in data:
            value = data.get("finding_fingerprint")
            if isinstance(value, str) and value:
                fingerprints.append(value)
        if "finding_fingerprints" in data:
            values = data.get("finding_fingerprints")
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, str):
                        fingerprints.append(item)
        for fp in [item for item in fingerprints if isinstance(item, str) and item]:
            entry = fingerprint_index.setdefault(
                fp,
                {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "evidence_ids": [],
                },
            )
            first_seen = entry.get("first_seen")
            last_seen = entry.get("last_seen")
            if timestamp and (first_seen is None or timestamp < first_seen):
                entry["first_seen"] = timestamp
            if timestamp and (last_seen is None or timestamp > last_seen):
                entry["last_seen"] = timestamp
            if event_id:
                evidence_ids = entry.get("evidence_ids")
                if isinstance(evidence_ids, list):
                    evidence_ids.append(str(event_id))

    aggregates: dict[str, dict] = {}
    for result in http_findings:
        rule_id = result.get("ruleId", "")
        if not rule_id:
            continue
        message = result.get("message", {}).get("text", "")
        location = result.get("locations", [{}])[0]
        uri = (
            location.get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri", "")
        )
        props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
        fingerprint = props.get("finding_fingerprint")
        if not fingerprint:
            fingerprints = result.get("partialFingerprints", {})
            if isinstance(fingerprints, dict):
                fingerprint = fingerprints.get("primary")

        severity = "unknown"
        if isinstance(props.get("severity"), str):
            severity = props.get("severity")
        aggregate = aggregates.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "summary": message or f"{rule_id} detected.",
                "severity": severity,
                "endpoints": set(),
                "first_seen": None,
                "last_seen": None,
                "evidence_ids": [],
            },
        )
        if uri:
            aggregate["endpoints"].add(uri)

        if fingerprint and fingerprint in fingerprint_index:
            meta = fingerprint_index[fingerprint]
            first_seen = meta.get("first_seen")
            last_seen = meta.get("last_seen")
            if first_seen and (aggregate["first_seen"] is None or first_seen < aggregate["first_seen"]):
                aggregate["first_seen"] = first_seen
            if last_seen and (aggregate["last_seen"] is None or last_seen > aggregate["last_seen"]):
                aggregate["last_seen"] = last_seen
            aggregate["evidence_ids"].extend(meta.get("evidence_ids", []))

    aggregated_list = []
    for entry in aggregates.values():
        endpoints = sorted(entry["endpoints"])
        max_list = 10
        evidence_ids = sorted(set(entry["evidence_ids"]))
        entry_out = {
            "rule_id": entry["rule_id"],
            "summary": entry["summary"],
            "severity": entry["severity"],
            "count": len(endpoints),
            "first_seen": entry["first_seen"] or "unknown",
            "last_seen": entry["last_seen"] or "unknown",
            "endpoints": endpoints[:max_list],
            "more_endpoints": max(0, len(endpoints) - max_list),
            "evidence_ids": evidence_ids[:5],
        }
        aggregated_list.append(entry_out)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        aggregated_list,
        key=lambda item: (severity_order.get(item["severity"], 9), item["rule_id"]),
    )


def _probe_request(scope: Scope, run_id: str, dry_run: bool) -> ToolRequest:
    ports = scope.allowed_ports
    per_attempt_timeout_ms = int(scope.per_attempt_timeout_ms)
    tool_timeout_ms = int(scope.tool_timeout_ms)
    return ToolRequest(
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


def _sorted_targets(targets: Iterable[dict]) -> list[dict]:
    return sorted(list(targets), key=_target_sort_key)


def _target_sort_key(item: dict) -> tuple[str, str, int, str, str, str]:
    parsed = urlparse(item["url"])
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    query = parsed.query or ""
    method = item.get("method", "HEAD")
    return (scheme, host, port, path, query, method)


def _sorted_events(events: list[dict]) -> list[dict]:
    return sorted(
        events,
        key=lambda item: (
            item.get("timestamp", ""),
            item.get("tool_name", ""),
            item.get("id", ""),
        ),
    )


def _target_id(method: str, url: str) -> str:
    value = f"{method}:{url}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _attempt_id(target_id: str, event_id: str) -> str:
    value = f"{target_id}:{event_id}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scheme(url: str) -> str:
    parsed = urlparse(url)
    return parsed.scheme


def _normalize_method(value: str) -> str:
    method = value.strip().upper()
    if not method:
        method = "HEAD"
    if method not in {"HEAD", "GET"}:
        raise ValueError(f"Unsupported HTTP method: {value}")
    return method


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ValueError(f"URL missing scheme: {url}")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError(f"URL missing host: {url}")
    if parsed.username or parsed.password:
        raise ValueError("URLs with credentials are not allowed")
    host = parsed.hostname.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{port}"
    canonical = f"{scheme}://{netloc}{path}"
    if parsed.query:
        canonical = f"{canonical}?{parsed.query}"
    return canonical


def _split_host_port(target: str) -> tuple[str | None, int | None]:
    if ":" not in target:
        return None, None
    host, port_str = target.split(":", 1)
    try:
        return host, int(port_str)
    except ValueError:
        return None, None


def _split_host_port_from_url(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _set_run_automation(sarif: dict, engagement_id: str, run_id: str, tool: str) -> None:
    for run in sarif.get("runs", []):
        run["runAutomationDetails"] = {"id": f"{engagement_id}:{run_id}:{tool}"}


def _normalize_sarif_runs(sarif: dict) -> None:
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return

    normalized: list[dict] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {}
        if driver.get("rules") is None:
            driver["rules"] = []
        tool["driver"] = driver
        run["tool"] = tool
        if run.get("results") is None:
            run["results"] = []
        if run.get("invocations") is None:
            run["invocations"] = []
        normalized.append(run)

    merged: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for run in normalized:
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "")
        run_id = run.get("runAutomationDetails", {}).get("id", "")
        key = (tool_name, run_id)
        if key not in merged:
            merged[key] = run
            order.append(key)
            continue
        existing = merged[key]
        existing_results = existing.get("results") or []
        existing_results.extend(run.get("results") or [])
        existing["results"] = existing_results
        existing_invocations = existing.get("invocations") or []
        existing_invocations.extend(run.get("invocations") or [])
        existing["invocations"] = existing_invocations
        existing_rules = existing.get("tool", {}).get("driver", {}).get("rules") or []
        extra_rules = run.get("tool", {}).get("driver", {}).get("rules") or []
        merged_rules: dict[str, dict] = {rule.get("id", f"rule-{index}"): rule for index, rule in enumerate(existing_rules)}
        for index, rule in enumerate(extra_rules):
            rule_id = rule.get("id", f"extra-{index}")
            if rule_id not in merged_rules:
                merged_rules[rule_id] = rule
        existing["tool"]["driver"]["rules"] = list(merged_rules.values())

    sarif["runs"] = [merged[key] for key in order]


def _estimate_http_timeout_ms(scope: Scope, http_targets: list[dict]) -> int:
    target_count = len(http_targets)
    if target_count == 0:
        return int(scope.tool_timeout_ms)
    rps = float(scope.max_rate)
    concurrency = max(1, int(scope.max_concurrency))
    per_attempt_ms = int(scope.per_attempt_timeout_ms)
    estimate_by_concurrency = (target_count * per_attempt_ms) / concurrency
    estimate_by_rps = 0.0
    if rps > 0:
        estimate_by_rps = (target_count / rps) * 1000
    estimate_ms = max(estimate_by_concurrency, estimate_by_rps)
    buffered_ms = int(estimate_ms + 2000)
    return max(int(scope.tool_timeout_ms), buffered_ms)


def _new_run_id() -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{now}-{hashlib.sha256(now.encode('utf-8')).hexdigest()[:8]}"


def _dns_domains_from_scope(scope: Scope) -> list[str]:
    candidates: list[str] = []
    for seed in scope.seed_targets:
        host = _normalize_dns_seed(seed)
        if host:
            candidates.append(host)
    if not candidates:
        for pattern in scope.allowed_domain_patterns():
            host = pattern.lstrip("*.") if pattern.startswith("*.") else pattern
            host = host.strip().lower()
            if not host or "*" in host:
                continue
            if _is_ip(host):
                continue
            candidates.append(host)
    return sorted({item for item in candidates if item})


def _dns_hosts_from_discoveries(discoveries: list[dict]) -> list[str]:
    hosts = {str(item.get("subdomain", "")).strip().lower() for item in discoveries}
    return sorted({item for item in hosts if item})


def _normalize_dns_seed(seed: str) -> str | None:
    value = str(seed).strip()
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        host = value.split(":", 1)[0]
    host = host.strip().lower().lstrip("*.")
    if not host or "*" in host:
        return None
    if _is_ip(host):
        return None
    return host


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
