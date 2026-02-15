# Python API Reference (Annotated)

> **Prerequisites**
> - Read architecture docs first.

This page is a practical API map for contributors.

It is intentionally concise: use it to find the right function quickly, then open the source for full behavior.

## Type and Error Conventions

- Dataclass payloads are strict-by-usage, not runtime-validated unless explicitly checked.
- Most operational failures return `blocked_reason` strings instead of raising.
- CLI argument/data parsing failures return exit code `2`.

Reading tip: start with `brain/cli/casm.py` and `brain/core/unified.py` for end-to-end flow, then drill into adapters and report/export modules.

## `brain/cli/casm.py`

### Utility Functions

| Function | Signature | Purpose | Errors / Edge Cases | Example |
|---|---|---|---|---|
| `_env_bool` | `(name: str, default: bool) -> bool` | Parse env bool defaults | Missing key -> default | `DRY_RUN` parsing |
| `_parse_bool` | `(value: str | None) -> bool` | Parse optional bool flag | `None` means implicit true | `--dry-run` |
| `_parse_formats` | `(value: str | None) -> set[str]` | Parse output format set | invalid format -> `ValueError` | `markdown,sarif,pdf` |
| `_load_domains_file` | `(path: str) -> list[str]` | Load domain list file | ignores blank/comment lines | DNS domains import |
| `_dns_domains_from_scope` | `(scope: Scope) -> list[str]` | Build DNS seeds from scope | filters wildcards/IP literals | DNS fallback targeting |
| `_normalize_dns_seed` | `(seed: str) -> str | None` | Convert URL/host seed to hostname | invalid/wildcard/IP -> `None` | URL to host extraction |
| `_is_ip` | `(value: str) -> bool` | IP literal detector | invalid string -> false | Seed filtering |

### Command Handlers

| Function | Signature | Side Effects | Return |
|---|---|---|---|
| `run_command` | `(args: argparse.Namespace) -> int` | reads scope, spawns probe, writes artifacts | exit code |
| `http_verify_command` | `(args) -> int` | builds request/inventory, executes HTTP tool | exit code |
| `unified_command` | `(args) -> int` | runs full pipeline, optional PDF | exit code |
| `_load_run_id` | `(evidence_path: Path) -> str` | reads evidence file | run_id |
| `dns_enum_command` | `(args) -> int` | DNS execution and artifact write | exit code |
| `evidence_command` | `(args) -> int` | streams filtered events to stdout | exit code |
| `migrate_command` | `(args) -> int` | migrates artifact directory | exit code |
| `diff_command` | `(args) -> int` | computes SARIF diff report | exit code |
| `main` | `() -> int` | CLI parser and dispatch | exit code |

## `brain/core/scope.py`

| Symbol | Signature | Purpose | Important Constraints |
|---|---|---|---|
| `Scope.from_file` | `(path: str) -> Scope` | Parse YAML/JSON scope config | unsupported extension -> `ValueError` |
| `Scope.snapshot` | `(self) -> dict` | Serialize scope state for tool payloads | includes all policy fields |
| `Scope.allowed_domain_patterns` | `(self) -> list[str]` | merge allowed domains/subdomains | dedupes appended patterns |
| `ScopeGuard.check_target` | `(host: str, port: int, protocol: str) -> ScopeDecision` | enforce protocol/port/domain-ip policy | protocol/port checks happen before host checks |
| `ScopeGuard.check_domain` | `(host: str) -> ScopeDecision` | domain-only policy path | exclusion overrides allowlist |
| `ScopeGuard.check_rate` | `(rps: float, concurrency: int) -> ScopeDecision` | enforce rate/concurrency ceilings | compares against scope maxes |

## `brain/core/orchestrator.py`

| Function | Signature | Purpose | Side Effects |
|---|---|---|---|
| `Orchestrator.run` | `(scope_path: str, dry_run: bool) -> dict` | probe pipeline | filesystem writes + publisher call |
| `Orchestrator._new_run_id` | `() -> str` | timestamp+uuid run ID | none |
| `_build_run_result_evidence` | `(engagement_id, run_id, tool_name, tool_version, status, duration_ms, blocked_reason) -> Evidence` | synthesize final run event | none |

## `brain/core/version.py`

| Function | Signature | Purpose | Side Effects |
|---|---|---|---|
| `get_casm_version` | `() -> str` | resolve installed package version with git/dev fallback | subprocess call when package metadata unavailable |

## `brain/core/http_verify.py`

| Function | Signature | Purpose | Edge Cases |
|---|---|---|---|
| `build_http_targets` | `(scope: Scope, seeds: list[str]) -> list[dict]` | derive HTTP targets from seeds | URL seeds preserved if allowed protocol |
| `build_http_verify_request` | `(scope, run_id, dry_run, run_dir) -> HttpVerifyRequest` | compose request + output paths | always emits evidence/sarif output config |

## `brain/core/dns_enum.py`

Key functions:

- `run_dns_enum`, `execute_dns_enum`, `build_dns_config`, `normalize_domains`, `filter_domains`
- `build_dns_events`, `build_dns_sarif`, `render_dns_report`
- `_event`, `target_hash`, `dns_fingerprint`

Primary side effects:

- writes evidence/SARIF/report files (in `run_dns_enum`)
- subprocess execution through `DnsEnumGateway`

Primary error modes:

- blocked reasons from tool (`dry_run`, `tool_not_found`, etc.)
- malformed tool output lists are normalized to empty lists

## `brain/core/unified.py`

Major API:

- `run_unified(...) -> UnifiedOutputs`
- target derivation/import/normalization:
  - `derive_http_targets`
  - `load_targets_file`
  - `normalize_targets`
  - `build_import_inventory`
  - `build_unified_inventory`
- evidence/SARIF/report composition:
  - `merge_evidence`
  - `write_evidence`
  - `write_unified_sarif`
  - `render_unified_report`

Helper set (canonicalization and deterministic IDs):

- `_target_id`, `_attempt_id`, `_normalize_url`, `_normalize_method`
- `_sorted_targets`, `_sorted_events`
- `_estimate_http_timeout_ms`
- DNS host derivation helpers

Important validation behavior:

- `_normalize_method` only allows `HEAD`/`GET`.
- `_normalize_url` rejects missing scheme/host and embedded credentials.
- `load_targets_file` raises `ValueError` for malformed harness files.

## `brain/core/inventory.py`

| Function | Signature | Purpose |
|---|---|---|
| `build_probe_inventory` | `(scope: Scope) -> list[TargetRecord]` | inventory for probe seeds/ports |
| `build_http_verify_inventory` | `(scope, urls, https_ports) -> list[TargetRecord]` | inventory for HTTP targets |
| `write_inventory` | `(path: str, records: list[TargetRecord]) -> str` | persist inventory JSONL |

## `brain/core/evidence_view.py`

| Function | Signature | Purpose | Errors |
|---|---|---|---|
| `parse_timestamp` | `(value: str) -> datetime` | parse RFC3339-like timestamp | invalid format -> `ValueError` |
| `EvidenceStream.__iter__` | `() -> iterator` | lazy filtered event stream | strict mode raises on bad lines |
| `load_evidence` | `(path: str, filters: EvidenceFilter) -> EvidenceStream` | stream factory | file errors propagate |

## Reporting/Export Modules

- `brain/core/report.py`: `render_report` and risk/recommendation helpers.
- `brain/core/sarif.py`: `build_sarif` and severity/fingerprint helpers.
- `brain/core/diff.py`: `diff_sarif`, `render_diff_report` and fingerprint loaders.
- `brain/core/migrate.py`: `migrate_run` and per-artifact migration helpers.
- `brain/core/redaction.py`: `redact_text`, `redact_data`.
- `brain/core/url_canonical.py`: `canonicalize_url`.

## PDF Modules

- `brain/core/pdf_styles.py`
  - `_hex_color`, `get_casm_styles`
- `brain/core/pdf_report.py`
  - Top-level API: `generate_pdf_report`
  - Section builders: `create_cover_page`, `create_executive_summary`, `create_diff_section`, etc.
  - Load/transform helpers: `_load_evidence`, `_load_sarif_findings`, `_diff_dns`, `_collect_trend_data`, etc.

`generate_pdf_report` error cases:

- missing `evidence.jsonl` -> `FileNotFoundError`
- invalid branding values are downgraded with warnings to stderr

## Adapter/Port APIs

| Symbol | Signature | Purpose |
|---|---|---|
| `ToolGatewayAdapter.run` | `(request: ToolRequest) -> ToolResult` | probe subprocess execution + mapping |
| `HttpVerifyGateway.run` | `(payload: dict) -> dict` | HTTP tool subprocess adapter |
| `DnsEnumGateway.run` | `(payload: dict) -> dict` | DNS tool subprocess adapter |
| `FileSystemEvidenceStore.write` | `(engagement_id, run_id, tool_name, tool_version, findings, evidence, report_md, tool_stderr=None, tool_stdout=None) -> dict` | redacted artifact persistence |
| `NoopPublisher.publish` | `(run_summary: dict) -> None` | no-op publish implementation |

## Data Structures (Python)

### Core dataclasses

- `Evidence`
  - Fields: `id`, `timestamp`, `type`, `target`, `data`, plus optional metadata fields.
  - Invariant: persisted evidence should include `schema_version`, `status`, `duration_ms`.
- `Finding`
  - Fields: `id`, `title`, `severity`, `target`, `evidence_ids`, `summary`, `timestamp`.
- `ToolRequest`
  - Fields align with probe request schema.
- `ToolResult`
  - `blocked_reason` controls blocked/error semantics in orchestration.

Additional dataclasses:

- `Scope`, `ScopeDecision`
- `TargetRecord`
- `EvidenceFilter`, `EvidenceLoadStats`
- `MigrationStats`
- `UnifiedOutputs`, `ImportSummary`
- `DnsEnumOutputs`
- PDF structs: `FindingRecord`, `SummaryStats`, `BaselineInfo`, `TrendEntry`, `SarifRecord`
