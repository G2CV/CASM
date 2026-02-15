
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from brain.adapters.dns_enum_gateway import DnsEnumGateway
from brain.core.models import Evidence
from brain.core.schema_version import SCHEMA_VERSION
from brain.core.scope import Scope, ScopeGuard


@dataclass
class DnsEnumOutputs:
    evidence: list[Evidence]
    events: list[dict]
    discoveries: list[dict]
    wildcards: list[dict]
    sarif: dict
    report: str
    blocked_reason: str | None


def run_dns_enum(
    scope: Scope,
    run_id: str,
    domains: list[str],
    out_dir: str,
    tool_path: str,
    dry_run: bool = False,
    overrides: dict | None = None,
) -> DnsEnumOutputs:
    """Run DNS enumeration and persist evidence, SARIF, and report artifacts.

    Args:
        scope (Scope): Scope configuration and limits.
        run_id (str): Run identifier for artifact namespacing.
        domains (list[str]): Domains to enumerate (may be filtered by scope).
        out_dir (str): Output directory for artifacts.
        tool_path (str): Path to the DNS enumeration binary.
        dry_run (bool): When True, tool should avoid network I/O.
        overrides (dict | None): Optional config overrides for this run.

    Returns:
        DnsEnumOutputs: Parsed outputs plus rendered report content.
    """
    outputs = execute_dns_enum(
        scope=scope,
        run_id=run_id,
        domains=domains,
        tool_path=tool_path,
        dry_run=dry_run,
        overrides=overrides,
    )
    events = outputs.events
    evidence = outputs.evidence
    sarif = outputs.sarif
    report = outputs.report
    discoveries = outputs.discoveries
    wildcards = outputs.wildcards
    blocked_reason = outputs.blocked_reason

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    evidence_path = out / "evidence.jsonl"
    with evidence_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    sarif_path = out / "results.sarif"
    sarif_path.write_text(json.dumps(sarif, indent=2, sort_keys=True), encoding="utf-8")
    report_path = out / "report.md"
    report_path.write_text(report, encoding="utf-8")

    return DnsEnumOutputs(
        evidence=evidence,
        events=events,
        discoveries=discoveries,
        wildcards=wildcards,
        sarif=sarif,
        report=report,
        blocked_reason=blocked_reason,
    )


def execute_dns_enum(
    scope: Scope,
    run_id: str,
    domains: list[str],
    tool_path: str,
    dry_run: bool = False,
    overrides: dict | None = None,
) -> DnsEnumOutputs:
    """Execute DNS enumeration and normalize tool output.

    Args:
        scope (Scope): Scope config used for guard checks and defaults.
        run_id (str): Run identifier for evidence/SARIF metadata.
        domains (list[str]): Candidate domains for enumeration.
        tool_path (str): Path to the DNS enumeration binary.
        dry_run (bool): When True, tool should avoid network I/O.
        overrides (dict | None): Optional config overrides.

    Returns:
        DnsEnumOutputs: Tool outputs expanded into evidence and report artifacts.

    Notes:
        Domain filtering is performed before invoking the tool to ensure it
        never receives out-of-scope inputs.
    """
    config = build_dns_config(scope, domains, overrides)
    guard = ScopeGuard(scope)
    allowed_domains, blocked_domains = filter_domains(config["domains"], guard)
    config["domains"] = allowed_domains

    gateway = DnsEnumGateway(tool_path=tool_path, timeout_ms=scope.tool_timeout_ms)
    payload = {
        "engagement_id": scope.engagement_id,
        "run_id": run_id,
        "dry_run": dry_run,
        "config": config,
    }

    response = gateway.run(payload)
    blocked_reason = response.get("blocked_reason")
    tool_version = response.get("tool_version") or "dev"
    discoveries = response.get("discoveries", []) if isinstance(response.get("discoveries"), list) else []
    queries = response.get("queries", []) if isinstance(response.get("queries"), list) else []
    errors = response.get("errors", []) if isinstance(response.get("errors"), list) else []
    wildcards = response.get("wildcards", []) if isinstance(response.get("wildcards"), list) else []

    events = build_dns_events(
        scope.engagement_id,
        run_id,
        tool_version,
        discoveries=discoveries,
        queries=queries,
        errors=errors,
        wildcards=wildcards,
        blocked_domains=blocked_domains,
    )
    evidence = [Evidence(**event) for event in events]
    sarif = build_dns_sarif(scope.engagement_id, run_id, tool_version, discoveries, wildcards)
    report = render_dns_report(scope, run_id, discoveries, wildcards, blocked_reason)

    return DnsEnumOutputs(
        evidence=evidence,
        events=events,
        discoveries=discoveries,
        wildcards=wildcards,
        sarif=sarif,
        report=report,
        blocked_reason=blocked_reason,
    )


def build_dns_config(scope: Scope, domains: list[str], overrides: dict | None) -> dict:
    """Build a normalized DNS enumeration config from scope + overrides.

    Args:
        scope (Scope): Source of default DNS enumeration settings.
        domains (list[str]): Candidate domains to include.
        overrides (dict | None): Optional overrides (including nested dicts).

    Returns:
        dict: Config payload for the DNS enumeration tool.

    Notes:
        Overrides merge the nested active_discovery config to avoid clobbering
        scope defaults with partial overrides.
    """
    cfg = dict(scope.dns_enumeration or {})
    cfg.setdefault("enabled", False)
    cfg.setdefault("passive_sources", ["crt.sh"])
    cfg.setdefault("active_discovery", {})
    cfg.setdefault("check_zone_transfer", False)
    cfg.setdefault("detect_wildcard", True)
    cfg.setdefault("record_types", ["A", "AAAA", "CNAME"])
    cfg.setdefault("max_consecutive_failures", 20)

    active_cfg = dict(cfg.get("active_discovery") or {})
    active_cfg.setdefault("enabled", False)
    active_cfg.setdefault("rate_limit", int(scope.max_rate))
    active_cfg.setdefault("timeout", int(scope.per_attempt_timeout_ms))
    active_cfg.setdefault("max_depth", 1)
    active_cfg.setdefault("concurrency", int(scope.max_concurrency))
    cfg["active_discovery"] = active_cfg

    cfg["rate_limit"] = int(cfg.get("rate_limit", int(scope.max_rate)))
    cfg["timeout"] = int(cfg.get("timeout", int(scope.per_attempt_timeout_ms)))
    cfg["max_depth"] = int(cfg.get("max_depth", 1))
    cfg["domains"] = normalize_domains(domains)

    if overrides:
        cfg.update({key: value for key, value in overrides.items() if value is not None})
        if "active_discovery" in overrides and isinstance(overrides["active_discovery"], dict):
            merged = dict(active_cfg)
            merged.update(overrides["active_discovery"])
            cfg["active_discovery"] = merged

    wordlist = cfg.get("wordlist_path")
    if not wordlist:
        cfg["wordlist_path"] = str(Path("wordlists") / "common-subdomains.txt")

    return cfg


def normalize_domains(domains: list[str]) -> list[str]:
    seen = set()
    normalized = []
    for item in domains:
        value = str(item).strip().lower().rstrip(".")
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return sorted(normalized)


def filter_domains(domains: list[str], guard: ScopeGuard) -> tuple[list[str], list[tuple[str, str]]]:
    """Split domains into allowed and blocked lists with reasons.

    Args:
        domains (list[str]): Candidate domain list.
        guard (ScopeGuard): Guard used to enforce scope policy.

    Returns:
        tuple[list[str], list[tuple[str, str]]]: Allowed domains and blocked
        domains with the blocking reason.

    Notes:
        Keeping blocked reasons enables reporting and auditability.
    """
    allowed: list[str] = []
    blocked: list[tuple[str, str]] = []
    for domain in domains:
        decision = guard.check_domain(domain)
        if decision.allowed:
            allowed.append(domain)
        else:
            blocked.append((domain, decision.reason or "domain_out_of_scope"))
    return allowed, blocked


def build_dns_events(
    engagement_id: str,
    run_id: str,
    tool_version: str,
    discoveries: list[dict],
    queries: list[dict],
    errors: list[dict],
    wildcards: list[dict],
    blocked_domains: list[tuple[str, str]],
) -> list[dict]:
    """Render DNS discoveries/errors into evidence events.

    Args:
        engagement_id (str): Engagement identifier for event metadata.
        run_id (str): Run identifier for event metadata.
        tool_version (str): Tool version to include in evidence.
        discoveries (list[dict]): Tool discovery records.
        queries (list[dict]): Tool query records.
        errors (list[dict]): Tool error records.
        wildcards (list[dict]): Wildcard detections.
        blocked_domains (list[tuple[str, str]]): Domains removed by scope guard.

    Returns:
        list[dict]: Evidence events for persistence.
    """
    events: list[dict] = []
    for domain, reason in blocked_domains:
        events.append(
            _event(
                event_type="dns_error",
                target=domain,
                data={"domain": domain, "error": reason, "status": "blocked"},
                engagement_id=engagement_id,
                run_id=run_id,
                tool_version=tool_version,
            )
        )

    for item in discoveries:
        subdomain = str(item.get("subdomain", ""))
        record_type = str(item.get("record_type", ""))
        values = item.get("values") if isinstance(item.get("values"), list) else []
        data = {
            "domain": item.get("domain"),
            "subdomain": subdomain,
            "record_type": record_type,
            "values": values,
            "source": item.get("source"),
            "discovery_method": item.get("discovery_method"),
            "first_seen": item.get("first_seen") or item.get("timestamp"),
            "finding_fingerprint": dns_fingerprint(subdomain, record_type),
        }
        events.append(
            _event(
                event_type="dns_discovery",
                target=subdomain,
                data=data,
                engagement_id=engagement_id,
                run_id=run_id,
                tool_version=tool_version,
                timestamp=item.get("timestamp"),
            )
        )

    for item in queries:
        subdomain = str(item.get("subdomain", ""))
        record_type = str(item.get("record_type", ""))
        data = {
            "domain": item.get("domain"),
            "subdomain": subdomain,
            "record_type": record_type,
            "source": item.get("source"),
            "discovery_method": item.get("discovery_method"),
            "status": item.get("status"),
            "error": item.get("error"),
            "duration_ms": item.get("duration_ms"),
        }
        events.append(
            _event(
                event_type="dns_query",
                target=subdomain or str(item.get("domain", "")),
                data=data,
                engagement_id=engagement_id,
                run_id=run_id,
                tool_version=tool_version,
                timestamp=item.get("timestamp"),
                status=item.get("status"),
                duration_ms=item.get("duration_ms"),
            )
        )

    for item in errors:
        subdomain = str(item.get("subdomain", ""))
        data = {
            "domain": item.get("domain"),
            "subdomain": subdomain,
            "record_type": item.get("record_type"),
            "source": item.get("source"),
            "discovery_method": item.get("discovery_method"),
            "error": item.get("error"),
        }
        events.append(
            _event(
                event_type="dns_error",
                target=subdomain or str(item.get("domain", "")),
                data=data,
                engagement_id=engagement_id,
                run_id=run_id,
                tool_version=tool_version,
                timestamp=item.get("timestamp"),
                status="error",
            )
        )

    for item in wildcards:
        domain = str(item.get("domain", ""))
        data = {
            "domain": domain,
            "record_type": item.get("record_type"),
            "values": item.get("values"),
            "source": item.get("source"),
        }
        events.append(
            _event(
                event_type="dns_wildcard_detected",
                target=domain,
                data=data,
                engagement_id=engagement_id,
                run_id=run_id,
                tool_version=tool_version,
                timestamp=item.get("timestamp"),
                status="warning",
            )
        )

    return events


def build_dns_sarif(
    engagement_id: str,
    run_id: str,
    tool_version: str,
    discoveries: list[dict],
    wildcards: list[dict],
) -> dict:
    rules = [
        {
            "id": "DNS_SUBDOMAIN_DISCOVERED",
            "shortDescription": {"text": "New subdomain discovered."},
        },
        {
            "id": "DNS_WILDCARD_DETECTED",
            "shortDescription": {"text": "Wildcard DNS detected."},
        },
    ]

    results: list[dict] = []
    for item in discoveries:
        subdomain = item.get("subdomain")
        record_type = item.get("record_type")
        values = item.get("values") if isinstance(item.get("values"), list) else []
        fingerprint = dns_fingerprint(str(subdomain), str(record_type))
        results.append(
            {
                "ruleId": "DNS_SUBDOMAIN_DISCOVERED",
                "level": "note",
                "message": {"text": f"New subdomain discovered: {subdomain}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"dns://{subdomain}"}
                        }
                    }
                ],
                "properties": {
                    "engagement_id": engagement_id,
                    "run_id": run_id,
                    "record_type": record_type,
                    "ip_addresses": values,
                    "discovery_source": item.get("source"),
                    "first_seen": item.get("first_seen") or item.get("timestamp"),
                    "finding_fingerprint": fingerprint,
                },
                "partialFingerprints": {"primary": fingerprint},
            }
        )

    for item in wildcards:
        domain = item.get("domain")
        values = item.get("values") if isinstance(item.get("values"), list) else []
        results.append(
            {
                "ruleId": "DNS_WILDCARD_DETECTED",
                "level": "warning",
                "message": {"text": f"Wildcard DNS detected: {domain}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"dns://{domain}"}
                        }
                    }
                ],
                "properties": {
                    "engagement_id": engagement_id,
                    "run_id": run_id,
                    "record_type": item.get("record_type"),
                    "values": values,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CASM",
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"schema_version": SCHEMA_VERSION},
                "runAutomationDetails": {"id": f"{engagement_id}:{run_id}:dns_enum"},
            }
        ],
        "properties": {"schema_version": SCHEMA_VERSION},
    }


def render_dns_report(
    scope: Scope,
    run_id: str,
    discoveries: list[dict],
    wildcards: list[dict],
    blocked_reason: str | None,
) -> str:
    lines = [
        "# CASM DNS Enumeration Report",
        "## Continuous Attack Surface Monitoring",
        "",
        f"Report schema: {SCHEMA_VERSION}",
        "",
        f"Engagement: {scope.engagement_id}",
        f"Run: {run_id}",
    ]
    if blocked_reason:
        lines.extend(["", f"Status: blocked ({blocked_reason})"])
    lines.extend(["", "## DNS Enumeration Results"])
    lines.append(f"Discovered subdomains: {len(discoveries)}")
    for item in discoveries[:20]:
        values = item.get("values") if isinstance(item.get("values"), list) else []
        value_str = ", ".join(values) if values else "-"
        lines.append(
            f"- {item.get('subdomain')} -> {item.get('record_type')} {value_str} ({item.get('source')})"
        )

    if wildcards:
        lines.extend(["", "## DNS Configuration Issues"])
        for item in wildcards:
            values = item.get("values") if isinstance(item.get("values"), list) else []
            value_str = ", ".join(values) if values else "-"
            lines.append(f"- Wildcard DNS detected: {item.get('domain')} -> {value_str}")

    return "\n".join(lines)


def _event(
    event_type: str,
    target: str,
    data: dict,
    engagement_id: str,
    run_id: str,
    tool_version: str,
    timestamp: str | None = None,
    status: str | None = None,
    duration_ms: int | None = None,
) -> dict:
    event_id = f"dns-{uuid.uuid4().hex[:8]}"
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    target_id = target_hash(target)
    payload = {
        "id": event_id,
        "timestamp": ts,
        "type": event_type,
        "target": target,
        "target_id": target_id,
        "data": data,
        "schema_version": SCHEMA_VERSION,
        "engagement_id": engagement_id,
        "run_id": run_id,
        "tool_name": "dns_enum",
        "tool_version": tool_version,
        "status": status or "success",
        "duration_ms": int(duration_ms or 0),
    }
    return payload


def target_hash(domain: str) -> str:
    value = domain.strip().lower()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def dns_fingerprint(subdomain: str, record_type: str) -> str:
    value = f"{subdomain.lower()}|{record_type.upper()}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
