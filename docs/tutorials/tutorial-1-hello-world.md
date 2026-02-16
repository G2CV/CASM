# Tutorial 1: Hello World (5 min)

> **Prerequisites**
> - macOS/Linux terminal
> - Python 3.11+
> - Go 1.21+

## Goal

Run your first CASM scan in dry-run mode and inspect generated artifacts.

## Steps

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
# Optional (from PyPI): python -m pip install g2cv-casm
python -m pip install -e .
make build-hands
make test
casm run probe --scope scopes/scope.example.yaml --dry-run
```

Expected behavior:

- Command returns success.
- No network probing occurs (`dry_run=true`).
- A run directory is created under `runs/eng-123/<run_id>/`.

Inspect output:

```bash
ls runs/eng-123
```

⚠️ Warning: Do not disable scope guard checks for initial experiments.
