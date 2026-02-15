# How To Profile Performance

> **Prerequisites**
> - You can run local scans against controlled targets.

## Python Timing (orchestration)

Use built-in run metrics and wall-clock timing:

```bash
time casm run unified --config scopes/scope.yaml --dry-run=false
```

Inspect `duration_ms` fields in `evidence.jsonl`.

## Go CPU/Memory profiling

For new tools, add optional `pprof` hooks in non-production builds.

Current repo does not ship persistent benchmark artifacts, so use local reproducible harnesses:

1. Fixed target set
2. Fixed timeout/rate/concurrency
3. Repeat N runs
4. Compare median and p95 elapsed time

## Rate/Concurrency tuning heuristics

- Increase `max_concurrency` only while timeout/error rates stay stable.
- Set `tool_timeout_ms` above estimated total work duration.
- Keep `max_rate` below external system limits.

⚠️ Warning: High concurrency with broad scope can create unintended load even in safe-check mode.
