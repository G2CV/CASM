# Function Signature Matrix Appendix

This appendix is the fastest way to confirm a function contract without opening the source file first.

It is generated from production Python signatures in `brain/**/*.py` (tests excluded), so every section follows the same shape and stays easy to scan.

How to read it:
- `Required` means "no default value in the signature".
- `Errors` lists only explicit `raise` statements in that function body.
- Dependency/runtime exceptions can still propagate even when `Errors` is empty.
- Use the `Source` line in each section to jump straight to implementation details.

## `DnsEnumGateway.run`

- Source: `brain/adapters/dns_enum_gateway.py:15`
- Signature: `DnsEnumGateway.run(payload: dict) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `payload` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `FileSystemEvidenceStore.write`

- Source: `brain/adapters/evidence_store_fs.py:17`
- Signature: `FileSystemEvidenceStore.write(engagement_id: str, run_id: str, tool_name: str | None, tool_version: str | None, findings: list[Finding], evidence: list[Evidence], report_md: str, tool_stderr: str | None = None, tool_stdout: str | None = None) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `tool_name` | `str | None` | `yes` | `` |
| `tool_version` | `str | None` | `yes` | `` |
| `findings` | `list[Finding]` | `yes` | `` |
| `evidence` | `list[Evidence]` | `yes` | `` |
| `report_md` | `str` | `yes` | `` |
| `tool_stderr` | `str | None` | `no` | `None` |
| `tool_stdout` | `str | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `HttpVerifyGateway.run`

- Source: `brain/adapters/http_verify_gateway.py:15`
- Signature: `HttpVerifyGateway.run(payload: dict) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `payload` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `NoopPublisher.publish`

- Source: `brain/adapters/publisher_noop.py:9`
- Signature: `NoopPublisher.publish(run_summary: dict) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `run_summary` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ToolGatewayAdapter.__init__`

- Source: `brain/adapters/tool_gateway.py:19`
- Signature: `ToolGatewayAdapter.__init__(tool_path: str, scope_guard: ScopeGuard, timeout_ms: int = 5000) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `tool_path` | `str` | `yes` | `` |
| `scope_guard` | `ScopeGuard` | `yes` | `` |
| `timeout_ms` | `int` | `no` | `5000` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ToolGatewayAdapter.run`

- Source: `brain/adapters/tool_gateway.py:24`
- Signature: `ToolGatewayAdapter.run(request: ToolRequest) -> ToolResult`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `request` | `ToolRequest` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `ToolResult` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `run_command`

- Source: `brain/cli/casm.py:126`
- Signature: `run_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `http_verify_command`

- Source: `brain/cli/casm.py:138`
- Signature: `http_verify_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `unified_command`

- Source: `brain/cli/casm.py:162`
- Signature: `unified_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `dns_enum_command`

- Source: `brain/cli/casm.py:225`
- Signature: `dns_enum_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `evidence_command`

- Source: `brain/cli/casm.py:274`
- Signature: `evidence_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `migrate_command`

- Source: `brain/cli/casm.py:322`
- Signature: `migrate_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `diff_command`

- Source: `brain/cli/casm.py:341`
- Signature: `diff_command(args: argparse.Namespace) -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `args` | `argparse.Namespace` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `main`

- Source: `brain/cli/casm.py:356`
- Signature: `main() -> int`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| — | — | — | — |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `int` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `diff_sarif`

- Source: `brain/core/diff.py:26`
- Signature: `diff_sarif(old_path: str, new_path: str, tool_filter: str | None = 'http_verify') -> DiffResult`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `old_path` | `str` | `yes` | `` |
| `new_path` | `str` | `yes` | `` |
| `tool_filter` | `str | None` | `no` | `'http_verify'` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `DiffResult` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `render_diff_report`

- Source: `brain/core/diff.py:58`
- Signature: `render_diff_report(diff: DiffResult, old_label: str, new_label: str, include_unchanged: bool = False) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `diff` | `DiffResult` | `yes` | `` |
| `old_label` | `str` | `yes` | `` |
| `new_label` | `str` | `yes` | `` |
| `include_unchanged` | `bool` | `no` | `False` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `run_dns_enum`

- Source: `brain/core/dns_enum.py:28`
- Signature: `run_dns_enum(scope: Scope, run_id: str, domains: list[str], out_dir: str, tool_path: str, dry_run: bool = False, overrides: dict | None = None) -> DnsEnumOutputs`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `domains` | `list[str]` | `yes` | `` |
| `out_dir` | `str` | `yes` | `` |
| `tool_path` | `str` | `yes` | `` |
| `dry_run` | `bool` | `no` | `False` |
| `overrides` | `dict | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `DnsEnumOutputs` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `execute_dns_enum`

- Source: `brain/core/dns_enum.py:89`
- Signature: `execute_dns_enum(scope: Scope, run_id: str, domains: list[str], tool_path: str, dry_run: bool = False, overrides: dict | None = None) -> DnsEnumOutputs`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `domains` | `list[str]` | `yes` | `` |
| `tool_path` | `str` | `yes` | `` |
| `dry_run` | `bool` | `no` | `False` |
| `overrides` | `dict | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `DnsEnumOutputs` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_dns_config`

- Source: `brain/core/dns_enum.py:160`
- Signature: `build_dns_config(scope: Scope, domains: list[str], overrides: dict | None) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `domains` | `list[str]` | `yes` | `` |
| `overrides` | `dict | None` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `normalize_domains`

- Source: `brain/core/dns_enum.py:211`
- Signature: `normalize_domains(domains: list[str]) -> list[str]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `domains` | `list[str]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[str]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `filter_domains`

- Source: `brain/core/dns_enum.py:223`
- Signature: `filter_domains(domains: list[str], guard: ScopeGuard) -> tuple[list[str], list[tuple[str, str]]]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `domains` | `list[str]` | `yes` | `` |
| `guard` | `ScopeGuard` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `tuple[list[str], list[tuple[str, str]]]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_dns_events`

- Source: `brain/core/dns_enum.py:248`
- Signature: `build_dns_events(engagement_id: str, run_id: str, tool_version: str, discoveries: list[dict], queries: list[dict], errors: list[dict], wildcards: list[dict], blocked_domains: list[tuple[str, str]]) -> list[dict]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `tool_version` | `str` | `yes` | `` |
| `discoveries` | `list[dict]` | `yes` | `` |
| `queries` | `list[dict]` | `yes` | `` |
| `errors` | `list[dict]` | `yes` | `` |
| `wildcards` | `list[dict]` | `yes` | `` |
| `blocked_domains` | `list[tuple[str, str]]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[dict]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_dns_sarif`

- Source: `brain/core/dns_enum.py:386`
- Signature: `build_dns_sarif(engagement_id: str, run_id: str, tool_version: str, discoveries: list[dict], wildcards: list[dict]) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `tool_version` | `str` | `yes` | `` |
| `discoveries` | `list[dict]` | `yes` | `` |
| `wildcards` | `list[dict]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `render_dns_report`

- Source: `brain/core/dns_enum.py:480`
- Signature: `render_dns_report(scope: Scope, run_id: str, discoveries: list[dict], wildcards: list[dict], blocked_reason: str | None) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `discoveries` | `list[dict]` | `yes` | `` |
| `wildcards` | `list[dict]` | `yes` | `` |
| `blocked_reason` | `str | None` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `target_hash`

- Source: `brain/core/dns_enum.py:549`
- Signature: `target_hash(domain: str) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `domain` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `dns_fingerprint`

- Source: `brain/core/dns_enum.py:554`
- Signature: `dns_fingerprint(subdomain: str, record_type: str) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `subdomain` | `str` | `yes` | `` |
| `record_type` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `parse_timestamp`

- Source: `brain/core/evidence_view.py:31`
- Signature: `parse_timestamp(value: str) -> datetime`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `value` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `datetime` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| `ValueError` | Explicit `raise ValueError(...)` in body |

## `EvidenceStream.__init__`

- Source: `brain/core/evidence_view.py:57`
- Signature: `EvidenceStream.__init__(path: str, filters: EvidenceFilter) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `path` | `str` | `yes` | `` |
| `filters` | `EvidenceFilter` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `load_evidence`

- Source: `brain/core/evidence_view.py:107`
- Signature: `load_evidence(path: str, filters: EvidenceFilter) -> EvidenceStream`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `path` | `str` | `yes` | `` |
| `filters` | `EvidenceFilter` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `EvidenceStream` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_http_targets`

- Source: `brain/core/http_verify.py:17`
- Signature: `build_http_targets(scope: Scope, seeds: list[str]) -> list[dict]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `seeds` | `list[str]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[dict]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_http_verify_request`

- Source: `brain/core/http_verify.py:51`
- Signature: `build_http_verify_request(scope: Scope, run_id: str, dry_run: bool, run_dir: str) -> HttpVerifyRequest`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `dry_run` | `bool` | `yes` | `` |
| `run_dir` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `HttpVerifyRequest` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_probe_inventory`

- Source: `brain/core/inventory.py:27`
- Signature: `build_probe_inventory(scope: Scope) -> list[TargetRecord]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[TargetRecord]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_http_verify_inventory`

- Source: `brain/core/inventory.py:50`
- Signature: `build_http_verify_inventory(scope: Scope, urls: list[str], https_ports: list[int]) -> list[TargetRecord]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `urls` | `list[str]` | `yes` | `` |
| `https_ports` | `list[int]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[TargetRecord]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `write_inventory`

- Source: `brain/core/inventory.py:79`
- Signature: `write_inventory(path: str, records: list[TargetRecord]) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `path` | `str` | `yes` | `` |
| `records` | `list[TargetRecord]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `migrate_run`

- Source: `brain/core/migrate.py:20`
- Signature: `migrate_run(input_dir: str, output_dir: str, strict: bool = False) -> MigrationStats`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `input_dir` | `str` | `yes` | `` |
| `output_dir` | `str` | `yes` | `` |
| `strict` | `bool` | `no` | `False` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `MigrationStats` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| `FileNotFoundError` | Explicit `raise FileNotFoundError(...)` in body |

## `Orchestrator.__init__`

- Source: `brain/core/orchestrator.py:22`
- Signature: `Orchestrator.__init__(tool_gateway: ToolGateway, evidence_store: EvidenceStore, publisher: Publisher) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `tool_gateway` | `ToolGateway` | `yes` | `` |
| `evidence_store` | `EvidenceStore` | `yes` | `` |
| `publisher` | `Publisher` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `Orchestrator.run`

- Source: `brain/core/orchestrator.py:32`
- Signature: `Orchestrator.run(scope_path: str, dry_run: bool) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope_path` | `str` | `yes` | `` |
| `dry_run` | `bool` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `generate_pdf_report`

- Source: `brain/core/pdf_report.py:48`
- Signature: `generate_pdf_report(engagement_id: str, run_id: str, output_dir: Path, evidence_store: object | None, branding_config: Optional[dict] = None, diff_config: Optional[dict] = None) -> Path`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `output_dir` | `Path` | `yes` | `` |
| `evidence_store` | `object | None` | `yes` | `` |
| `branding_config` | `Optional[dict]` | `no` | `None` |
| `diff_config` | `Optional[dict]` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `Path` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| `FileNotFoundError` | Explicit `raise FileNotFoundError(...)` in body |

## `calculate_summary_stats`

- Source: `brain/core/pdf_report.py:243`
- Signature: `calculate_summary_stats(evidence_path: Path, targets_path: Path, sarif_path: Path) -> SummaryStats`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `evidence_path` | `Path` | `yes` | `` |
| `targets_path` | `Path` | `yes` | `` |
| `sarif_path` | `Path` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `SummaryStats` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_cover_page`

- Source: `brain/core/pdf_report.py:291`
- Signature: `create_cover_page(engagement_id: str, run_id: str, report_date: str, styles: dict, branding: Optional[dict]) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `report_date` | `str` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |
| `branding` | `Optional[dict]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_executive_summary`

- Source: `brain/core/pdf_report.py:326`
- Signature: `create_executive_summary(summary: SummaryStats, styles: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `summary` | `SummaryStats` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_table_of_contents`

- Source: `brain/core/pdf_report.py:356`
- Signature: `create_table_of_contents(styles: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `styles` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_scope_section`

- Source: `brain/core/pdf_report.py:365`
- Signature: `create_scope_section(summary: SummaryStats, styles: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `summary` | `SummaryStats` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_dns_section`

- Source: `brain/core/pdf_report.py:378`
- Signature: `create_dns_section(summary: SummaryStats, styles: dict, palette: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `summary` | `SummaryStats` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |
| `palette` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_findings_section`

- Source: `brain/core/pdf_report.py:400`
- Signature: `create_findings_section(findings: list[FindingRecord], styles: dict, palette: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `findings` | `list[FindingRecord]` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |
| `palette` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_port_scan_section`

- Source: `brain/core/pdf_report.py:421`
- Signature: `create_port_scan_section(summary: SummaryStats, styles: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `summary` | `SummaryStats` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_appendix`

- Source: `brain/core/pdf_report.py:431`
- Signature: `create_appendix(summary: SummaryStats, styles: dict, output_dir: Path) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `summary` | `SummaryStats` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |
| `output_dir` | `Path` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_severity_table`

- Source: `brain/core/pdf_report.py:440`
- Signature: `create_severity_table(severity_counts: dict, styles: dict) -> Table`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `severity_counts` | `dict` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `Table` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_dns_tables`

- Source: `brain/core/pdf_report.py:459`
- Signature: `create_dns_tables(dns_discoveries: list[dict], styles: dict, palette: dict) -> list`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `dns_discoveries` | `list[dict]` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |
| `palette` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_port_table`

- Source: `brain/core/pdf_report.py:500`
- Signature: `create_port_table(port_events: list[dict], styles: dict) -> Table`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `port_events` | `list[dict]` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `Table` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `create_diff_section`

- Source: `brain/core/pdf_report.py:709`
- Signature: `create_diff_section(engagement_id: str, run_id: str, output_dir: Path, summary: SummaryStats, styles: dict, settings: dict) -> list[Flowable]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `output_dir` | `Path` | `yes` | `` |
| `summary` | `SummaryStats` | `yes` | `` |
| `styles` | `dict` | `yes` | `` |
| `settings` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[Flowable]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `get_casm_styles`

- Source: `brain/core/pdf_styles.py:20`
- Signature: `get_casm_styles(branding_config: Optional[dict] = None) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `branding_config` | `Optional[dict]` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `redact_text`

- Source: `brain/core/redaction.py:17`
- Signature: `redact_text(value: str) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `value` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `redact_data`

- Source: `brain/core/redaction.py:30`
- Signature: `redact_data(value: Any) -> Any`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `value` | `Any` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `Any` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `render_report`

- Source: `brain/core/report.py:11`
- Signature: `render_report(scope: Scope, run_id: str, findings: list[Finding], evidence: list[Evidence], blocked_reason: str | None, dry_run: bool) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `findings` | `list[Finding]` | `yes` | `` |
| `evidence` | `list[Evidence]` | `yes` | `` |
| `blocked_reason` | `str | None` | `yes` | `` |
| `dry_run` | `bool` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_sarif`

- Source: `brain/core/sarif.py:8`
- Signature: `build_sarif(findings: list[Finding], engagement_id: str, run_id: str, tool_name: str, tool_version: str) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `findings` | `list[Finding]` | `yes` | `` |
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `tool_name` | `str` | `yes` | `` |
| `tool_version` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `Scope.from_file`

- Source: `brain/core/scope.py:45`
- Signature: `Scope.from_file(path: str) -> 'Scope'`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `path` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `'Scope'` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| `ValueError` | Explicit `raise ValueError(...)` in body |

## `Scope.snapshot`

- Source: `brain/core/scope.py:86`
- Signature: `Scope.snapshot() -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| — | — | — | — |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `Scope.allowed_domain_patterns`

- Source: `brain/core/scope.py:118`
- Signature: `Scope.allowed_domain_patterns() -> list[str]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| — | — | — | — |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[str]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ScopeGuard.__init__`

- Source: `brain/core/scope.py:138`
- Signature: `ScopeGuard.__init__(scope: Scope) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ScopeGuard.check_target`

- Source: `brain/core/scope.py:142`
- Signature: `ScopeGuard.check_target(host: str, port: int, protocol: str) -> ScopeDecision`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `host` | `str` | `yes` | `` |
| `port` | `int` | `yes` | `` |
| `protocol` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `ScopeDecision` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ScopeGuard.check_domain`

- Source: `brain/core/scope.py:162`
- Signature: `ScopeGuard.check_domain(host: str) -> ScopeDecision`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `host` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `ScopeDecision` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ScopeGuard.check_rate`

- Source: `brain/core/scope.py:178`
- Signature: `ScopeGuard.check_rate(rps: float, concurrency: int) -> ScopeDecision`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `rps` | `float` | `yes` | `` |
| `concurrency` | `int` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `ScopeDecision` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `run_unified`

- Source: `brain/core/unified.py:47`
- Signature: `run_unified(scope_path: str, out_dir: str, sarif_mode: str, probe_tool_path: str, http_tool_path: str, dry_run: bool, targets_file: str | None = None, detailed_report: bool = False, dns_tool_path: str | None = None, dns_enabled: bool | None = None, dns_wordlist: str | None = None) -> UnifiedOutputs`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope_path` | `str` | `yes` | `` |
| `out_dir` | `str` | `yes` | `` |
| `sarif_mode` | `str` | `yes` | `` |
| `probe_tool_path` | `str` | `yes` | `` |
| `http_tool_path` | `str` | `yes` | `` |
| `dry_run` | `bool` | `yes` | `` |
| `targets_file` | `str | None` | `no` | `None` |
| `detailed_report` | `bool` | `no` | `False` |
| `dns_tool_path` | `str | None` | `no` | `None` |
| `dns_enabled` | `bool | None` | `no` | `None` |
| `dns_wordlist` | `str | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `UnifiedOutputs` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `derive_http_targets`

- Source: `brain/core/unified.py:211`
- Signature: `derive_http_targets(scope: Scope, probe_result: ToolResult) -> list[dict]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `probe_result` | `ToolResult` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[dict]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `load_targets_file`

- Source: `brain/core/unified.py:246`
- Signature: `load_targets_file(path: str) -> list[dict]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `path` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[dict]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| `ValueError` | Explicit `raise ValueError(...)` in body |

## `normalize_targets`

- Source: `brain/core/unified.py:276`
- Signature: `normalize_targets(targets: Iterable[dict]) -> list[dict]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `targets` | `Iterable[dict]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[dict]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_import_inventory`

- Source: `brain/core/unified.py:300`
- Signature: `build_import_inventory(scope: Scope, targets: list[dict], source_path: str, total_targets: int) -> tuple[list[TargetRecord], list[dict], ImportSummary]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `targets` | `list[dict]` | `yes` | `` |
| `source_path` | `str` | `yes` | `` |
| `total_targets` | `int` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `tuple[list[TargetRecord], list[dict], ImportSummary]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `build_unified_inventory`

- Source: `brain/core/unified.py:358`
- Signature: `build_unified_inventory(scope: Scope, http_targets: list[dict]) -> list[TargetRecord]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `http_targets` | `list[dict]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[TargetRecord]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `merge_evidence`

- Source: `brain/core/unified.py:399`
- Signature: `merge_evidence(scope: Scope, run_id: str, probe_result: ToolResult, http_evidence_path: str, http_result: dict, dns_events: list[dict] | None = None) -> list[dict]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `probe_result` | `ToolResult` | `yes` | `` |
| `http_evidence_path` | `str` | `yes` | `` |
| `http_result` | `dict` | `yes` | `` |
| `dns_events` | `list[dict] | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `list[dict]` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `write_evidence`

- Source: `brain/core/unified.py:469`
- Signature: `write_evidence(path: str, events: list[dict]) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `path` | `str` | `yes` | `` |
| `events` | `list[dict]` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `write_unified_sarif`

- Source: `brain/core/unified.py:477`
- Signature: `write_unified_sarif(out: Path, scope: Scope, run_id: str, sarif_mode: str, probe_result: ToolResult, http_sarif_path: str, dns_sarif: dict | None = None) -> tuple[str, str | None, str | None, str | None]`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `out` | `Path` | `yes` | `` |
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `sarif_mode` | `str` | `yes` | `` |
| `probe_result` | `ToolResult` | `yes` | `` |
| `http_sarif_path` | `str` | `yes` | `` |
| `dns_sarif` | `dict | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `tuple[str, str | None, str | None, str | None]` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `render_unified_report`

- Source: `brain/core/unified.py:530`
- Signature: `render_unified_report(scope: Scope, run_id: str, probe_result: ToolResult, http_sarif_path: str, evidence: list[dict], import_summary: ImportSummary | None = None, expected_http_targets: int | None = None, detailed_report: bool = False) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `scope` | `Scope` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `probe_result` | `ToolResult` | `yes` | `` |
| `http_sarif_path` | `str` | `yes` | `` |
| `evidence` | `list[dict]` | `yes` | `` |
| `import_summary` | `ImportSummary | None` | `no` | `None` |
| `expected_http_targets` | `int | None` | `no` | `None` |
| `detailed_report` | `bool` | `no` | `False` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `canonicalize_url`

- Source: `brain/core/url_canonical.py:7`
- Signature: `canonicalize_url(raw_url: str) -> str`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `raw_url` | `str` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `str` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `EvidenceStore.write`

- Source: `brain/ports/evidence_store.py:11`
- Signature: `EvidenceStore.write(engagement_id: str, run_id: str, tool_name: str | None, tool_version: str | None, findings: list[Finding], evidence: list[Evidence], report_md: str, tool_stderr: str | None = None, tool_stdout: str | None = None) -> dict`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `engagement_id` | `str` | `yes` | `` |
| `run_id` | `str` | `yes` | `` |
| `tool_name` | `str | None` | `yes` | `` |
| `tool_version` | `str | None` | `yes` | `` |
| `findings` | `list[Finding]` | `yes` | `` |
| `evidence` | `list[Evidence]` | `yes` | `` |
| `report_md` | `str` | `yes` | `` |
| `tool_stderr` | `str | None` | `no` | `None` |
| `tool_stdout` | `str | None` | `no` | `None` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `dict` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `Publisher.publish`

- Source: `brain/ports/publisher.py:9`
- Signature: `Publisher.publish(run_summary: dict) -> None`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `run_summary` | `dict` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `None` | `yes` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |

## `ToolGateway.run`

- Source: `brain/ports/tool_gateway.py:11`
- Signature: `ToolGateway.run(request: ToolRequest) -> ToolResult`

### Parameter Matrix

| Name | Type | Required | Default |
|---|---|---|---|
| `request` | `ToolRequest` | `yes` | `` |

### Return Matrix

| Position | Type | Nullable | Notes |
|---|---|---|---|
| `1` | `ToolResult` | `no` | Derived from annotation |

### Error Matrix

| Exception | Trigger |
|---|---|
| — | No explicit `raise` in function body |
