# Component Inventory

This is the quick map of the production codebase.

Use it when you need to answer questions like "where does this command route?" or "which module owns SARIF/report output?" before diving into implementation details.

## Python Components (`brain/`)

| Component | Purpose | Dependencies | Exports | State / Thread Safety | Performance Notes |
|---|---|---|---|---|---|
| `brain/cli/casm.py` | CLI entrypoint and command routing | `argparse`, core/adapters modules | `main()`, subcommand handlers | Stateless per call; process-local | O(n) over loaded records/events depending subcommand |
| `brain/core/models.py` | Shared dataclasses contracts | `dataclasses`, `typing` | `Evidence`, `Finding`, `ToolRequest`, `ToolResult` | Immutable-by-convention objects | Minimal overhead; serialization dominates |
| `brain/core/scope.py` | Scope parsing and policy guard | `yaml`, `ipaddress`, `fnmatch` | `Scope`, `ScopeGuard`, `ScopeDecision` | `ScopeGuard` precomputes CIDR list; read-only after init | O(patterns + CIDRs) per check |
| `brain/core/orchestrator.py` | Probe pipeline orchestrator | inventory, report, sarif, ports | `Orchestrator` | Stateless per run object | Linear in findings/evidence size |
| `brain/core/http_verify.py` | Build HTTP verify request payload | `urllib.parse`, `Scope` | `HttpVerifyRequest`, builders | Stateless | O(targets x ports x protocols) target expansion |
| `brain/core/dns_enum.py` | DNS run execution + normalization + report | DNS adapter, `ScopeGuard` | `DnsEnumOutputs`, DNS helpers | Stateless | O(events) transform + file write |
| `brain/core/unified.py` | Unified probe+dns+http orchestration | probe/http/dns modules | `run_unified`, utility functions | Stateless orchestration | Dominated by tool runtimes and evidence merge O(n log n) sort |
| `brain/core/inventory.py` | Build and write target inventory JSONL | `socket`, `ScopeGuard` | `TargetRecord`, inventory builders | Stateless | Optional DNS resolution can be slow/network-bound |
| `brain/core/evidence_view.py` | Stream/filter evidence JSONL | `json`, `datetime` | `EvidenceFilter`, `EvidenceStream`, `load_evidence` | `EvidenceStream.stats` mutable per iterator | Streaming O(n), constant memory |
| `brain/core/report.py` | Markdown report generator (probe) | `Counter`, models/scope | `render_report` | Stateless | O(findings + evidence) |
| `brain/core/sarif.py` | SARIF builder (probe) | models/schema version | `build_sarif` | Stateless | O(findings) |
| `brain/core/diff.py` | SARIF diff engine/report | `json`, `hashlib` | `DiffFinding`, `DiffResult`, diff funcs | Stateless | O(results) + sort |
| `brain/core/migrate.py` | Run artifact migration | `json`, `pathlib` | `MigrationStats`, `migrate_run` | Stateless | O(file lines) |
| `brain/core/redaction.py` | Secret redaction utility | `re` | `redact_text`, `redact_data` | Stateless regex set | O(text length / object size) |
| `brain/core/url_canonical.py` | URL canonicalization | `urllib.parse` | `canonicalize_url` | Stateless | O(url length + query params log n) |
| `brain/core/version.py` | Runtime version resolution | `importlib.metadata`, `subprocess` | `get_casm_version` | Stateless | O(1) metadata read or git invocation |
| `brain/core/pdf_styles.py` | PDF style palette factory | `reportlab` | `get_casm_styles` | Stateless | Negligible |
| `brain/core/pdf_report.py` | PDF report generation and baseline diff section | `reportlab`, diff module | `generate_pdf_report` + helpers | Stateless per generation | O(events + findings + table rendering) |
| `brain/core/schema_version.py` | Global schema constant | none | `SCHEMA_VERSION` | Constant | none |
| `brain/adapters/tool_gateway.py` | Probe subprocess adapter and mapping | `subprocess`, `ScopeGuard` | `ToolGatewayAdapter` | Stateless except config fields | Subprocess + JSON parse dominates |
| `brain/adapters/http_verify_gateway.py` | HTTP tool subprocess adapter | `subprocess` | `HttpVerifyGateway` | Stateless except config fields | Subprocess time dominates |
| `brain/adapters/dns_enum_gateway.py` | DNS tool subprocess adapter | `subprocess` | `DnsEnumGateway` | Stateless except config fields | Subprocess time dominates |
| `brain/adapters/evidence_store_fs.py` | File persistence for evidence/report/logs | `json`, redaction | `FileSystemEvidenceStore` | Stateless except base dir | O(lines written) |
| `brain/adapters/publisher_noop.py` | No-op publisher | none | `NoopPublisher` | Stateless | none |
| `brain/ports/tool_gateway.py` | Tool gateway protocol boundary | `typing.Protocol` | `ToolGateway` | Interface only | none |
| `brain/ports/evidence_store.py` | Evidence persistence boundary | `typing.Protocol` | `EvidenceStore` | Interface only | none |
| `brain/ports/publisher.py` | Publisher boundary | `typing.Protocol` | `Publisher` | Interface only | none |

## Go Components (`hands/cmd/*`)

| Component | Purpose | Dependencies | Exports | State / Thread Safety | Performance Notes |
|---|---|---|---|---|---|
| `hands/cmd/probe/main.go` | TCP connect scanning tool | stdlib net/json/time | `main`, request/response structs | Sequential scanner, no shared mutable concurrency | O(targets x ports) |
| `hands/cmd/http_verify/main.go` | HTTP header/TLS verification tool | stdlib http/tls + sync/atomic | `main`, `run`, many helpers | Worker pool, mutex-protected evidence writer, atomic IDs | O(targets + redirects + observations) |
| `hands/cmd/dns_enum/main.go` | DNS orchestrator (passive+active) | stdlib + internal dns files | `main`, `run`, collector methods | Mutex around shared collector | O(domains x record_types x candidates) |
| `hands/cmd/dns_enum/active.go` | Active DNS query engine | `github.com/miekg/dns`, goroutines | active query functions | Worker pool + atomic breaker + limiter | Potentially high cardinality on large wordlists |
| `hands/cmd/dns_enum/passive.go` | crt.sh passive discovery | stdlib http/json | `queryCrtSh` | Stateless per call | Network/API latency bound |
| `hands/cmd/dns_enum/resolver.go` | DNS resolver abstraction/retry | `github.com/miekg/dns` | `DNSResolver` and helpers | Resolver object immutable after init | Retry adds bounded latency |
| `hands/cmd/dns_enum/wordlist.go` | Wordlist loader | stdlib bufio | `loadWordlist` | Stateless | O(lines in file) |

## Contract and Configuration Files

| File | Purpose | Validation |
|---|---|---|
| `contracts/schemas/tool_request.schema.json` | Probe request schema | JSON Schema draft 2020-12 |
| `contracts/schemas/tool_response.schema.json` | Probe response schema | JSON Schema draft 2020-12 |
| `contracts/schemas/http_verify_request.schema.json` | HTTP verify request schema | JSON Schema draft 2020-12 |
| `contracts/schemas/http_verify_response.schema.json` | HTTP verify response schema | JSON Schema draft 2020-12 |
| `contracts/schemas/dns_enum_request.schema.json` | DNS enum request schema | JSON Schema draft 2020-12 |
| `contracts/schemas/dns_enum_response.schema.json` | DNS enum response schema | JSON Schema draft 2020-12 |
| `scopes/scope.example.yaml` / `scopes/scope.yaml` | User-editable engagement config | Parsed by `Scope.from_file` |
| `.env.example` | Env defaults | Parsed by `_env_bool` etc. |
