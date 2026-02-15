# How To Debug Cross-Language Issues

## Symptom to Cause Mapping

| Symptom | Likely Cause | Fix |
|---|---|---|
| `tool_not_found` | binary missing | run `make build-hands` |
| `tool_timeout` | timeout too low / target unreachable | increase timeout, inspect stderr tail |
| `invalid_tool_output` | stdout contains invalid JSON | ensure tool prints JSON only |
| `tool_error` | Go panic or non-zero exit | run tool directly and inspect logs |

## Practical Workflow

1. Run command with small target set.
2. Inspect run directory for `tool_stderr.log` / `tool_stdout.partial.log`.
3. Re-run Go tool standalone by piping known request fixture.

```bash
cat contracts/fixtures/http_verify_request.json | hands/bin/http_verify
```

4. Validate response against schema.

## Race and Concurrency Debugging (Go)

```bash
cd hands && go test -race ./...
```
