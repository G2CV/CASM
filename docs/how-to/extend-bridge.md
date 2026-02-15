# How To Extend the Python-Go Interface

## Steps

1. Update JSON schema in `contracts/schemas/`.
2. Update Go request/response struct.
3. Update Python payload builder and adapter parser.
4. Add fixture examples in `contracts/fixtures/`.
5. Add/adjust tests on both sides.

## Backward Compatibility Rule

- Prefer additive fields.
- Default safely in Go (`defaults`/`applyDefaults`) and Python.
- Preserve existing reason codes.

## Validation Strategy

- Validate schema shape in tests.
- Run a full end-to-end CLI command to ensure serialization compatibility.

```bash
make test
```
