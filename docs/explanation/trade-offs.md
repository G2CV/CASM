# Trade-offs and Alternatives

## Chosen vs Rejected Approaches

| Topic | Chosen | Rejected | Reason |
|---|---|---|---|
| Runtime integration | subprocess + JSON | gRPC or cgo/FFI | lower coupling, simpler deployment/debugging |
| Evidence storage | filesystem JSONL | DB-first model | easier portability and audit exports |
| Scope enforcement | centralized Python guard + Go checks | tool-local checks only | policy consistency + defense in depth |
| Reporting | Markdown + SARIF + optional PDF | single format only | supports executive and automation audiences |

## Trade-offs Accepted

- JSON serialization overhead per tool call.
- Duplicate validation in both Python and Go for safety.
- Artifact-heavy output directories require retention policy.

## Why not REST between brain and hands?

- Local subprocess calls avoid service lifecycle management.
- No local network port exposure.
- Fewer moving parts for CI and offline runs.
