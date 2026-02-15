# How To Run Tests

## Unit + Integration-in-repo

```bash
make test
```

Equivalent commands:

```bash
python -m pytest brain/tests
cd hands && go test ./...
```

## End-to-End Manual Test

```bash
casm run unified --config scopes/scope.yaml --dry-run=false
casm evidence --path runs/<engagement>/<run>/evidence.jsonl --limit 10
casm diff --old runs/<baseline>/results.sarif --new runs/<current>/results.sarif
```

## Troubleshooting

- Python import error: activate virtualenv and reinstall requirements.
- Go build error: verify `go version` is 1.21+.
- Network test flakiness: prefer dry-run or localhost fixtures for deterministic testing.
