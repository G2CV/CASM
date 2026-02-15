# Contributing to CASM

Thanks for your interest in contributing.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pip install -e .
make build-hands
```

## Local Checks Before PR

```bash
.venv/bin/pytest brain/tests
go test ./...  # from hands/
.venv/bin/mkdocs build
```

## Coding Guidelines

- Keep changes focused and small.
- Add or update tests for behavior changes.
- Preserve scope-guard safety behavior.
- Avoid introducing heavy dependencies without strong justification.
- Keep docs and examples aligned with code changes.

## Pull Requests

- Describe why the change is needed.
- Summarize user-facing impact.
- Mention test coverage for the change.
- Link related issues if applicable.

## Security Reports

Please report vulnerabilities privately. See `SECURITY.md`.
