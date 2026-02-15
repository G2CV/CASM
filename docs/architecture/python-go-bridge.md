# Python-Go Interface Contract

> **Prerequisites**
> - You understand JSON Schema basics.

## Contract Summary

The Python-Go bridge is a strict JSON-over-stdio contract.

- Probe contract:
  - Request schema: `contracts/schemas/tool_request.schema.json`
  - Response schema: `contracts/schemas/tool_response.schema.json`
- HTTP verify contract:
  - Request schema: `contracts/schemas/http_verify_request.schema.json`
  - Response schema: `contracts/schemas/http_verify_response.schema.json`
- DNS enum contract:
  - Request schema: `contracts/schemas/dns_enum_request.schema.json`
  - Response schema: `contracts/schemas/dns_enum_response.schema.json`

## Message Encoding

- UTF-8 JSON objects
- One request object over stdin
- One response object over stdout
- Additional telemetry written to files (`evidence.jsonl`, `results.sarif`)

## Success and Failure Semantics

| Condition | Surface in Python | Meaning |
|---|---|---|
| subprocess timeout | `blocked_reason=tool_timeout` | Tool exceeded configured timeout |
| non-zero exit | `blocked_reason=tool_error` | Tool process failed |
| invalid JSON stdout | `blocked_reason=invalid_tool_output` | Contract violation |
| request blocked by policy | `blocked_reason=<reason>` | Scope/rate/dry-run/abort policy prevented execution |
| `ok=true` with outputs | normal success | Findings/evidence valid |

Common reason codes:

- `aborted`
- `dry_run`
- `tool_not_found`
- `tool_timeout`
- `tool_error`
- `invalid_tool_output`
- `domain_out_of_scope`
- `ip_out_of_scope`
- `port_not_allowed`
- `protocol_not_allowed`
- `rate_limit_exceeded`
- `concurrency_limit_exceeded`

## Example: Successful Probe Interaction

```json
{
  "tool_name": "probe",
  "engagement_id": "eng-localhost-labs",
  "run_id": "20260206T201512Z-abc12345",
  "scope": {"allowed_ports": [8443], "allowed_protocols": ["tcp"]},
  "dry_run": false,
  "per_attempt_timeout_ms": 8000,
  "tool_timeout_ms": 10000,
  "rate_limit": {"rps": 2, "burst": 2, "concurrency": 1},
  "input": {"targets": [{"host": "localhost"}], "ports": [8443], "protocol": "tcp"}
}
```

```json
{
  "ok": true,
  "blocked_reason": null,
  "findings": [{"id": "fnd-1", "title": "Open TCP port", "severity": "low", "target": "localhost:8443", "evidence_ids": ["evi-1"], "summary": "TCP connection succeeded.", "timestamp": "2026-02-06T20:15:12.000Z"}],
  "evidence": [{"id": "evi-1", "type": "tcp_connect", "target": "localhost:8443", "status": "success", "duration_ms": 12, "schema_version": "1.0.0"}],
  "metrics": {"attempted": 1, "open_count": 1, "elapsed_ms": 13},
  "tool_name": "probe",
  "tool_version": "0.1.0"
}
```

## Example: Failed Interaction

Python adapter timeout mapping (from `ToolGatewayAdapter.run`):

```json
{
  "ok": false,
  "blocked_reason": "tool_timeout",
  "metrics": {"duration_ms": 5001},
  "raw_redacted": {
    "stderr": "...tail...",
    "stdout": "...tail..."
  },
  "tool_name": "probe"
}
```

## Panic and Crash Behavior

- There is no explicit panic-to-Python translation layer.
- If a Go panic terminates process with non-zero exit, Python maps it to `tool_error`.
- If a panic still emits malformed or partial stdout, Python maps to `invalid_tool_output`.

## FFI / C Bindings

- None in this repository.
- Integration is process-based (CLI tool binaries), not shared-library based.

## Boundary Type Mapping (Python <-> Go)

| Concept | Python Type | Go Type |
|---|---|---|
| Booleans | `bool` | `bool` |
| Integers | `int` | `int`/`int64` |
| Strings | `str` | `string` |
| Lists | `list[T]` | `[]T` |
| Dynamic object | `dict[str, Any]` | `map[string]any` |

Memory note:

- Because transport is JSON over pipes, there is no shared memory layout concern at runtime.
- Serialization cost is paid on each tool call, but keeps language boundary simple and safe.
