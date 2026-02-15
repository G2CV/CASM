# Data Flow and Sequences

> **Prerequisites**
> - You read `docs/architecture/overview.md` first.

## End-to-End Unified Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as casm CLI
    participant Scope as Scope/ScopeGuard
    participant U as unified.py
    participant P as probe (Go)
    participant D as dns_enum (Go)
    participant H as http_verify (Go)
    participant FS as runs/* artifacts

    User->>CLI: casm run unified --config scopes/scope.yaml
    CLI->>Scope: load scope + policy limits
    CLI->>U: run_unified(...)

    alt DNS enabled
      U->>D: stdin JSON dns request
      D-->>U: stdout JSON dns response
      U->>FS: write DNS evidence/events
    end

    alt targets file not provided
      U->>P: stdin JSON probe request
      P-->>U: stdout JSON probe response
    else targets file provided
      U->>U: load + normalize imported targets
    end

    U->>H: stdin JSON http_verify request
    H-->>FS: evidence.jsonl + results.sarif
    H-->>U: stdout JSON summary/results

    U->>U: merge evidence + normalize IDs + canonical URLs
    U->>FS: write merged evidence/targets/sarif/report
    CLI-->>User: print output paths
```

## Probe-Only Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant O as Orchestrator
    participant TG as ToolGatewayAdapter
    participant Probe as probe (Go)
    participant ES as FileSystemEvidenceStore

    User->>CLI: casm run probe --scope scopes/scope.yaml
    CLI->>O: run(scope_path, dry_run)
    O->>TG: run(ToolRequest)
    TG->>TG: ABORT_RUN / dry_run / scope/rate checks
    TG->>Probe: subprocess stdin JSON
    Probe-->>TG: stdout JSON ToolResponse
    TG-->>O: ToolResult
    O->>ES: write evidence/report/logs
    O->>O: build SARIF
    O-->>CLI: run summary
```

## Error Propagation Sequence

```mermaid
sequenceDiagram
    participant Python as Gateway Adapter
    participant Go as Tool Process
    participant CLI

    Python->>Go: start subprocess + send request JSON
    alt process timeout
      Python->>Python: blocked_reason=tool_timeout
    else non-zero exit
      Python->>Python: blocked_reason=tool_error
    else invalid stdout JSON
      Python->>Python: blocked_reason=invalid_tool_output
    else valid response with blocked_reason
      Python->>Python: preserve tool blocked_reason
    end
    Python-->>CLI: deterministic blocked status
```

## Data Lifecycle

1. User passes CLI arguments.
2. Scope file is parsed into `Scope` dataclass.
3. Scope/rate constraints are applied before tool execution.
4. Go tool emits response + telemetry files.
5. Python normalizes:
   - schema version
   - canonical URL fields
   - stable IDs (`target_id`, `attempt_id`, fingerprints)
6. Final outputs are written and later consumed by:
   - `casm evidence`
   - `casm diff`
   - PDF generator

## State Ownership

- **In-memory transient state**
  - Tool request/response objects
  - Aggregation maps (findings, fingerprints)
- **Persistent state**
  - Run artifact directory under `runs/`
  - No database in this repository

💡 Tip: Treat `evidence.jsonl` as the source-of-truth event log. Reports are derived views.
