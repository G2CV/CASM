# Setup for Absolute Beginners

If this is your first time running CASM, follow this page top-to-bottom and you should have a working local scan in a few minutes.

> **Prerequisites**
> - Linux or MacOS shell
> - Internet access for package install

## Required Versions

- Python: 3.11 or newer
- Go: 1.21 or newer

Check versions:

```bash
python3 --version
go version
```

## Step-by-Step Installation

1. Clone the repository.
2. Create and activate virtual environment.
3. Install Python dependencies and the local `casm` CLI entrypoint.
4. Build Go binaries used by scan commands.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pip install -e .
make build-hands
```

## Verify Installation

```bash
casm run probe --scope scopes/scope.example.yaml --dry-run
make test
```

If both commands succeed, your local setup is ready.

If `casm` is not found, reactivate the venv and run:

```bash
python -m pip install -e .
```

## Common Installation Errors

| Error | Cause | Fix |
|---|---|---|
| `command not found: go` | Go missing | install Go 1.21+ and reopen shell |
| `No module named brain` | venv not active | `source .venv/bin/activate` |
| `tool_not_found` | binaries not built | run `make build-hands` |
| SSL/TLS package install failures | corporate proxy/certs | configure pip/go proxy and CA settings |

💡 Tip: Keep `.venv` active in every shell where you run CASM.
