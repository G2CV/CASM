# How To Add a New Go Package/Tool

## Goal

Add a new execution tool under `hands/` that follows CASM contracts.

## Steps

1. Create command package (usually `hands/cmd/<tool_name>/main.go`).
2. Define request/response structs with JSON tags.
3. Read one request from stdin and write one response to stdout.
4. Keep response deterministic (sorted output where needed).
5. Add tests in same package.
6. Add build target in `Makefile`.
7. Add Python adapter in `brain/adapters`.
8. Wire command in CLI.

## Minimal main pattern

```go
reader := bufio.NewReader(os.Stdin)
var req ToolRequest
if err := json.NewDecoder(reader).Decode(&req); err != nil {
    // emit blocked invalid_request response
}
resp := run(req)
_ = json.NewEncoder(os.Stdout).Encode(resp)
```

⚠️ Warning: Return structured JSON failures; do not print arbitrary logs to stdout.
