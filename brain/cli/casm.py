from __future__ import annotations

"""CASM command-line interface entrypoint."""

import argparse
import ipaddress
import json
import os
import sys

from pathlib import Path
from urllib.parse import urlparse

from brain.adapters.evidence_store_fs import FileSystemEvidenceStore
from brain.adapters.http_verify_gateway import HttpVerifyGateway
from brain.adapters.publisher_noop import NoopPublisher
from brain.adapters.tool_gateway import ToolGatewayAdapter
from brain.core.evidence_view import EvidenceFilter, load_evidence, parse_timestamp
from brain.core.http_verify import build_http_verify_request
from brain.core.dns_enum import run_dns_enum
from brain.core.migrate import migrate_run
from brain.core.diff import diff_sarif, render_diff_report
from brain.core.unified import run_unified
from brain.core.pdf_report import generate_pdf_report
from brain.core.inventory import build_http_verify_inventory, write_inventory
from brain.core.orchestrator import Orchestrator
from brain.core.scope import Scope, ScopeGuard


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean from the environment with a safe default.

    Notes:
        CLI flags can still override this; env values only provide a baseline
        for convenience in automation.
    """
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes"}


def _parse_bool(value: str | None) -> bool:
    """Parse optional boolean flags that allow an implicit True value."""
    if value is None:
        return True
    return value.lower() in {"1", "true", "yes"}


def _parse_formats(value: str | None) -> set[str]:
    """Parse output formats from a comma-separated string.

    Supported values: markdown, sarif, pdf, all.
    """
    if not value or value == "all":
        return {"markdown", "sarif", "pdf"}
    formats = {item.strip().lower() for item in value.split(",") if item.strip()}
    allowed = {"markdown", "sarif", "pdf"}
    invalid = formats - allowed
    if invalid:
        raise ValueError(f"Unsupported format(s): {', '.join(sorted(invalid))}")
    return formats


def _load_domains_file(path: str) -> list[str]:
    """Load a domains list, ignoring blanks and comments."""
    domains: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            domains.append(value)
    return domains


def _dns_domains_from_scope(scope: Scope) -> list[str]:
    """Derive DNS enum candidates from scope when none are provided.

    Notes:
        This favors explicit seed targets and falls back to allowed domain
        patterns to avoid enumerating overly broad wildcards.
    """
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


def _normalize_dns_seed(seed: str) -> str | None:
    """Normalize DNS seeds to plain hostnames for enumeration."""
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
    """Treat IP literals as non-DNS seeds to avoid invalid enumeration."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def run_command(args: argparse.Namespace) -> int:
    """Run the probe pipeline for the provided scope."""
    scope = Scope.from_file(args.scope)
    scope_guard = ScopeGuard(scope)
    gateway = ToolGatewayAdapter(tool_path=args.tool_path, scope_guard=scope_guard)
    evidence_store = FileSystemEvidenceStore()
    orchestrator = Orchestrator(gateway, evidence_store, NoopPublisher())
    summary = orchestrator.run(scope_path=args.scope, dry_run=args.dry_run)
    print(f"Run complete: {summary}")
    return 0


def http_verify_command(args: argparse.Namespace) -> int:
    """Run HTTP verification with per-run artifacts in runs/ directory."""
    scope = Scope.from_file(args.scope)
    run_id = Orchestrator._new_run_id()
    run_dir = Path("runs") / scope.engagement_id / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    request = build_http_verify_request(scope, run_id, args.dry_run, str(run_dir))
    inventory = build_http_verify_inventory(
        scope,
        [target["url"] for target in request.payload["targets"]],
        scope.http_verify_https_ports,
    )
    write_inventory(str(run_dir / "targets.jsonl"), inventory)
    gateway = HttpVerifyGateway(tool_path=args.tool_path, timeout_ms=scope.tool_timeout_ms)
    result = gateway.run(request.payload)

    print(
        "Http verify complete: "
        f"run_id={run_id} evidence={request.evidence_path} sarif={request.sarif_path} result={result.get('summary')}"
    )
    return 0


def unified_command(args: argparse.Namespace) -> int:
    """Run the full unified pipeline and report merged artifacts."""
    out_dir = args.out
    if out_dir is None:
        scope = Scope.from_file(args.config)
        run_id = Orchestrator._new_run_id()
        out_dir = f"runs/{scope.engagement_id}/{run_id}"
    else:
        scope = Scope.from_file(args.config)

    outputs = run_unified(
        scope_path=args.config,
        out_dir=out_dir,
        sarif_mode=args.sarif_mode,
        probe_tool_path=args.probe_tool_path,
        http_tool_path=args.http_tool_path,
        dns_tool_path=args.dns_tool_path,
        dns_enabled=args.enable_dns_enum,
        dns_wordlist=args.dns_wordlist,
        dry_run=args.dry_run,
        targets_file=args.targets_file,
        detailed_report=args.detailed,
        report_lang=args.report_lang,
    )

    try:
        formats = _parse_formats(args.format)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if "pdf" in formats:
        try:
            run_id = _load_run_id(Path(outputs.evidence_path))
            pdf_path = generate_pdf_report(
                engagement_id=scope.engagement_id,
                run_id=run_id,
                output_dir=Path(out_dir),
                evidence_store=None,
                branding_config=scope.pdf_branding,
                diff_config=scope.pdf_diff,
                report_lang=args.report_lang,
            )
            print(f"PDF report created: {pdf_path}")
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(f"Failed to generate PDF report: {exc}", file=sys.stderr)

    print(
        "Unified run complete: "
        f"targets={outputs.targets_path} evidence={outputs.evidence_path} sarif={outputs.sarif_path} report={outputs.report_path}"
    )
    return 0


def _load_run_id(evidence_path: Path) -> str:
    with evidence_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            data = json.loads(line)
            run_id = data.get("run_id")
            if run_id:
                return str(run_id)
    raise ValueError("Unable to determine run_id from evidence")


def dns_enum_command(args: argparse.Namespace) -> int:
    """Run DNS enumeration with optional per-run overrides."""
    scope = Scope.from_file(args.config)
    run_id = Orchestrator._new_run_id()
    out_dir = args.out
    if out_dir is None:
        out_dir = f"runs/{scope.engagement_id}/{run_id}"

    domains = []
    if args.domain:
        domains.extend(args.domain)
    if args.domains_file:
        domains.extend(_load_domains_file(args.domains_file))
    if not domains:
        domains = _dns_domains_from_scope(scope)

    overrides = {}
    if args.passive_only:
        overrides["passive_only"] = True
        overrides.setdefault("active_discovery", {})["enabled"] = False
    if args.rate_limit is not None:
        overrides["rate_limit"] = args.rate_limit
    if args.timeout is not None:
        overrides["timeout"] = args.timeout
    if args.max_depth is not None:
        overrides["max_depth"] = args.max_depth
    if args.wordlist:
        overrides["wordlist_path"] = args.wordlist
        overrides.setdefault("active_discovery", {})["wordlist"] = args.wordlist
    if args.record_types:
        overrides["record_types"] = args.record_types

    outputs = run_dns_enum(
        scope=scope,
        run_id=run_id,
        domains=domains,
        out_dir=out_dir,
        tool_path=args.tool_path,
        dry_run=args.dry_run,
        overrides=overrides,
    )

    print(
        "DNS enumeration complete: "
        f"run_id={run_id} evidence={out_dir}/evidence.jsonl sarif={out_dir}/results.sarif"
    )
    return 0


def evidence_command(args: argparse.Namespace) -> int:
    """Stream evidence with server-side style filtering for large files."""
    try:
        since = parse_timestamp(args.since) if args.since else None
        until = parse_timestamp(args.until) if args.until else None
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if since and until and since > until:
        print("Invalid time range: --since must be <= --until", file=sys.stderr)
        return 2
    filters = EvidenceFilter(
        event_type=args.type,
        tool_name=args.tool,
        target_id=args.target_id,
        contains=args.contains,
        contains_scope=args.contains_scope,
        ignore_case=args.ignore_case,
        strict=args.strict,
        since=since,
        until=until,
        limit=args.limit,
    )
    records = load_evidence(args.path, filters)
    try:
        for event in records:
            print(json.dumps(event, sort_keys=True))
    except (ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if records.stats.invalid_json_lines:
        print(
            f"Skipped {records.stats.invalid_json_lines} invalid JSON line(s)",
            file=sys.stderr,
        )
    if records.stats.skipped_missing_timestamp:
        print(
            f"Skipped {records.stats.skipped_missing_timestamp} line(s) missing timestamp",
            file=sys.stderr,
        )
    if records.stats.skipped_bad_timestamp:
        print(
            f"Skipped {records.stats.skipped_bad_timestamp} line(s) with invalid timestamp",
            file=sys.stderr,
        )
    return 0


def migrate_command(args: argparse.Namespace) -> int:
    """Migrate a run directory forward to the current schema."""
    out_dir = args.out
    if out_dir is None:
        out_dir = f"{args.input}-migrated"
    try:
        stats = migrate_run(args.input, out_dir, strict=args.strict)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        "Migration complete: "
        f"evidence={stats.migrated_evidence} skipped_evidence={stats.skipped_evidence} "
        f"sarif={stats.migrated_sarif} skipped_sarif={stats.skipped_sarif} "
        f"report_updated={str(stats.report_updated).lower()} out={out_dir}"
    )
    return 0


def diff_command(args: argparse.Namespace) -> int:
    """Generate a SARIF diff report for regression tracking."""
    try:
        diff = diff_sarif(args.old, args.new, tool_filter=args.tool)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = render_diff_report(diff, args.old, args.new, include_unchanged=args.include_unchanged)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


def main() -> int:
    """CLI entrypoint and command registration."""
    parser = argparse.ArgumentParser(prog="casm")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a scan")
    run_subparsers = run_parser.add_subparsers(dest="mode", required=True)

    probe_parser = run_subparsers.add_parser("probe", help="Run probe tool")
    probe_parser.add_argument("--scope", required=True, help="Path to scope.yaml")
    probe_parser.add_argument(
        "--tool-path",
        default="hands/bin/probe",
        help="Path to probe tool binary",
    )
    probe_parser.add_argument(
        "--dry-run",
        nargs="?",
        const=True,
        default=_env_bool("DRY_RUN", True),
        type=_parse_bool,
        help="Run without executing tools (true/false)",
    )
    probe_parser.set_defaults(func=run_command)

    http_parser = run_subparsers.add_parser("http-verify", help="Run http_verify tool")
    http_parser.add_argument("--scope", required=True, help="Path to scope.yaml")
    http_parser.add_argument(
        "--tool-path",
        default="hands/bin/http_verify",
        help="Path to http_verify tool binary",
    )
    http_parser.add_argument(
        "--dry-run",
        nargs="?",
        const=True,
        default=_env_bool("DRY_RUN", True),
        type=_parse_bool,
        help="Run without executing tools (true/false)",
    )
    http_parser.set_defaults(func=http_verify_command)

    unified_parser = run_subparsers.add_parser("unified", help="Run unified probe + http_verify pipeline")
    unified_parser.add_argument("--config", required=True, help="Path to scope.yaml")
    unified_parser.add_argument("--out", default=None, help="Output directory for artifacts")
    unified_parser.add_argument(
        "--sarif-mode",
        choices=["local", "github"],
        default="local",
        help="SARIF output mode",
    )
    unified_parser.add_argument(
        "--probe-tool-path",
        default="hands/bin/probe",
        help="Path to probe tool binary",
    )
    unified_parser.add_argument(
        "--http-tool-path",
        default="hands/bin/http_verify",
        help="Path to http_verify tool binary",
    )
    unified_parser.add_argument(
        "--targets-file",
        default=None,
        help="Path to JSON targets file (imports targets instead of probe)",
    )
    unified_parser.add_argument(
        "--dry-run",
        nargs="?",
        const=True,
        default=_env_bool("DRY_RUN", True),
        type=_parse_bool,
        help="Run without executing tools (true/false)",
    )
    unified_parser.add_argument(
        "--enable-dns-enum",
        action="store_true",
        help="Enable DNS enumeration before http_verify",
    )
    unified_parser.add_argument(
        "--dns-tool-path",
        default="hands/bin/dns_enum",
        help="Path to dns_enum tool binary",
    )
    unified_parser.add_argument(
        "--dns-wordlist",
        default=None,
        help="Path to DNS enumeration wordlist",
    )
    unified_parser.add_argument(
        "--detailed",
        action="store_true",
        help="Include detailed http_verify findings in the report",
    )
    unified_parser.add_argument(
        "--format",
        default="all",
        help="Output formats: markdown,sarif,pdf or all",
    )
    unified_parser.add_argument(
        "--report-lang",
        choices=["en", "fr"],
        default="en",
        help="Report language for markdown/pdf outputs",
    )
    unified_parser.set_defaults(func=unified_command)

    dns_parser = run_subparsers.add_parser("dns-enum", help="Run dns_enum tool")
    dns_parser.add_argument("--config", required=True, help="Path to scope.yaml")
    dns_parser.add_argument(
        "--tool-path",
        default="hands/bin/dns_enum",
        help="Path to dns_enum tool binary",
    )
    dns_parser.add_argument("--out", default=None, help="Output directory for artifacts")
    dns_parser.add_argument("--domain", action="append", help="Domain to enumerate (repeatable)")
    dns_parser.add_argument("--domains-file", default=None, help="Path to domains list")
    dns_parser.add_argument("--wordlist", default=None, help="Path to wordlist file")
    dns_parser.add_argument("--passive-only", action="store_true", help="Only run passive sources")
    dns_parser.add_argument("--rate-limit", type=int, default=None, help="Queries per second")
    dns_parser.add_argument("--timeout", type=int, default=None, help="Query timeout in ms")
    dns_parser.add_argument("--max-depth", type=int, default=None, help="Max subdomain depth")
    dns_parser.add_argument(
        "--record-types",
        nargs="+",
        default=None,
        help="Record types to query (A AAAA CNAME MX TXT)",
    )
    dns_parser.add_argument(
        "--dry-run",
        nargs="?",
        const=True,
        default=_env_bool("DRY_RUN", True),
        type=_parse_bool,
        help="Run without executing tools (true/false)",
    )
    dns_parser.set_defaults(func=dns_enum_command)

    evidence_parser = subparsers.add_parser("evidence", help="View evidence.jsonl")
    evidence_parser.add_argument("--path", required=True, help="Path to evidence.jsonl")
    evidence_parser.add_argument("--type", default=None, help="Filter by event type")
    evidence_parser.add_argument("--tool", default=None, help="Filter by tool name")
    evidence_parser.add_argument("--target-id", default=None, help="Filter by target_id")
    evidence_parser.add_argument("--contains", default=None, help="Substring match")
    evidence_parser.add_argument(
        "--contains-scope",
        choices=["all", "message", "error", "data"],
        default="all",
        help="Choose which field(s) to search",
    )
    evidence_parser.add_argument(
        "--ignore-case",
        action="store_true",
        help="Case-insensitive contains matching",
    )
    evidence_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail fast on invalid JSON lines",
    )
    evidence_parser.add_argument("--limit", type=int, default=50, help="Limit number of events")
    evidence_parser.add_argument(
        "--since",
        default=None,
        help="Include events with timestamp >= value (RFC3339; UTC if no timezone)",
    )
    evidence_parser.add_argument(
        "--until",
        default=None,
        help="Include events with timestamp <= value (RFC3339; UTC if no timezone)",
    )
    evidence_parser.set_defaults(func=evidence_command)

    migrate_parser = subparsers.add_parser("migrate", help="Migrate a run directory to the latest schema")
    migrate_parser.add_argument("--input", required=True, help="Path to run directory")
    migrate_parser.add_argument("--out", default=None, help="Output directory for migrated artifacts")
    migrate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail fast on invalid JSON during migration",
    )
    migrate_parser.set_defaults(func=migrate_command)

    diff_parser = subparsers.add_parser("diff", help="Compare two SARIF result files")
    diff_parser.add_argument("--old", required=True, help="Path to old results.sarif")
    diff_parser.add_argument("--new", required=True, help="Path to new results.sarif")
    diff_parser.add_argument(
        "--tool",
        default="http_verify",
        help="Tool filter based on runAutomationDetails id suffix",
    )
    diff_parser.add_argument(
        "--include-unchanged",
        action="store_true",
        help="Include unchanged findings in the report",
    )
    diff_parser.add_argument("--out", default=None, help="Write report to a file")
    diff_parser.set_defaults(func=diff_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
