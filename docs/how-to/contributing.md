# Contributing Guide

## Principles

- Keep scope enforcement centralized (`ScopeGuard`).
- Keep tool execution behind adapter interfaces.
- Keep outputs deterministic (stable sorting/fingerprints).
- Keep tests offline-first and reproducible.

## Workflow

1. Create a focused branch.
2. Add/modify code in smallest coherent unit.
3. Add tests for all behavior changes.
4. Run:

```bash
make test
```

5. Update docs under `docs/` when behavior or contract changes.

## Commit Quality

- Explain **why** in commit message.
- Keep schema and fixture updates synchronized.
- Do not commit secrets or environment-specific credentials.

## Cross-Language Change Checklist

- [ ] Python payload updated
- [ ] Go struct updated
- [ ] JSON schema updated
- [ ] Fixtures updated
- [ ] Tests updated in both runtimes
- [ ] Reference docs updated
