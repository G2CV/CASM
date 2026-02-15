# Data Structures Reference

## Python Dataclasses

### `Evidence` (`brain/core/models.py`)

| Field | Type | Meaning |
|---|---|---|
| `id` | `str` | event identifier |
| `timestamp` | `str` | event timestamp (ISO/RFC3339 style) |
| `type` | `str` | event type (`tcp_connect`, `http_response`, etc.) |
| `target` | `str` | scanned target |
| `data` | `dict[str, Any]` | structured payload |
| `target_id` | `str | None` | stable target hash |
| `schema_version` | `str | None` | schema marker |
| metadata fields | optional | engagement/run/tool/status/duration |

Invariant: persisted events include schema/status/duration.

### `Finding`

Fields: `id`, `title`, `severity`, `target`, `evidence_ids`, `summary`, `timestamp`.

Invariant: `evidence_ids` references existing evidence lines from same run.

### `ToolRequest` and `ToolResult`

- `ToolRequest` mirrors probe request schema.
- `ToolResult` normalizes adapter output and blocked reason semantics.

## Go Structs and Serialization

All runtime exchange structs are JSON-tagged.

### Probe structs (`hands/cmd/probe/main.go`)

- `ToolRequest`: contract fields (`tool_name`, `engagement_id`, `run_id`, `scope`, `dry_run`, timeouts, rate_limit, input)
- `ToolResponse`: `ok`, `blocked_reason`, findings/evidence/metrics/tool metadata
- `Evidence`, `Finding`: schema-aligned event and finding records

### HTTP verify structs (`hands/cmd/http_verify/main.go`)

- Request: engagement/run/dry-run/profile/tls/scope/targets/limits/evidence/sarif
- Response: `summary` counters + `results`
- `ResultEntry` captures URL/method/status/final_url/headers/tls/observations/duration/error

### DNS enum structs (`hands/cmd/dns_enum/main.go`)

- Request: engagement/run/dry-run/config
- Response: discoveries/queries/errors/wildcards/metrics
- Discovery and telemetry event records are all JSON-tagged and timestamped

## Invariants and Consistency Rules

- Fingerprints must be stable for same semantic finding.
- Canonical URLs should normalize case/default ports/trailing slash/query ordering.
- `schema_version` should exist in persisted evidence and SARIF.
- run IDs follow timestamp-prefixed format for lexical ordering.

## Go <-> Python Memory Layout Considerations

- No shared memory boundary exists.
- Data is serialized/deserialized through JSON text.
- Implication: field naming/tag consistency matters more than binary layout.
