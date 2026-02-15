# How To Add a New Python Module

## Goal

Add new brain logic without breaking architecture boundaries.

## Steps

1. Choose package:
   - `brain/core` for domain logic
   - `brain/adapters` for IO/integration
   - `brain/ports` for protocol interfaces
2. Add dataclasses/contracts in `brain/core/models.py` when shared.
3. Keep side effects in adapters, not in core logic.
4. Add tests under `brain/tests/`.
5. Run:

```bash
python -m pytest brain/tests
```

## Module Checklist

- [ ] Type hints present
- [ ] Deterministic output ordering where relevant
- [ ] Redaction applied before persistence
- [ ] ScopeGuard enforcement for network-affecting paths
