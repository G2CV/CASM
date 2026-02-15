# CASM
## Continuous Attack Surface Monitoring

**EASM + Baseline Comparison + Evidence-First**

Know your attack surface. Track what changes.

CASM continuously maps your external attack surface and tracks what changed - 
turning security scanning into security intelligence.

## What is CASM?

CASM is an attack surface tracking and analysis system that:
- 🔍 **Discovers** - Maps your external attack surface (HTTP, DNS, TLS)
- ✅ **Verifies** - Checks security configurations and headers
- 📊 **Tracks** - Baseline comparison shows exactly what changed
- 📋 **Reports** - Evidence-ready compliance reporting (SARIF, Markdown, PDF)

Unlike traditional scanners that give you snapshots, CASM tracks changes over 
time - answering the critical question: "What's different from last week?"

## Principles

- Authorization-first. Operates only within explicit scope and rate limits.
- Safe verification by default. No destructive actions, no payloads, no brute force.
- Evidence-first. Findings are backed by raw, redacted evidence.
- Modular architecture. Brain (Python) orchestrates, Hands (Go) execute.

## Status

Current focus: EASM-style discovery + safe verification + evidence-first reporting.
- SARIF output for CI integration
- Evidence JSONL for automation
- A dual-audience Markdown report (executive + technical) for `casm run`.
- PDF reports with a "Changes Since Last Scan" section when a baseline exists.

## Safety model

CASM is designed for authorized testing only and enforces:
- Default dry-run mode
- Scope guard allowlists (domains, IPs, ports, protocols)
- Deterministic blocking with reason codes
- Rate limiting and concurrency caps

## Repository layout

`brain/`: Python orchestration + policy enforcement
- `core/`: Domain logic (scope, policy, findings, reporting)
- `ports/`: Interfaces (tool gateway, evidence store, publisher)
- `adapters/`: Implementations (tool runners)
- `cli/`: `casm` CLI entrypoint
- `tests/`: Offline-first unit tests

`hands/`: Go tools for safe verification
- `cmd/probe/`: TCP connect checks
- `cmd/http_verify/`: HTTP metadata and header checks
- `cmd/dns_enum/`: DNS enumeration (passive + active)
- `pkg/`: Shared code

`contracts/`: JSON schemas + fixtures
- `schemas/`: Tool request/response schemas
- `fixtures/`: Deterministic fixtures for tests

`runs/`: Evidence + reports output

---

## Requirements

- Python 3.11+ recommended (tested with 3.14)
- Go 1.21+

---

## Setup (recommended: venv)

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements.txt -r requirements-dev.txt
    python -m pip install -e .

Build the Go tools:

    make build-hands

Run DNS enumeration:

    casm run dns-enum --config scopes/scope.yaml --domain example.com

Run tests:

    make test

Run http_verify via CLI:

    casm run http-verify --scope scopes/scope.yaml --dry-run=false

Note: `casm run http-verify` writes `evidence.jsonl`, `results.sarif`, and `targets.jsonl` in `runs/<engagement>/<run>/` but does not generate a report yet.

Unified pipeline:

    casm run unified --config scopes/scope.yaml --sarif-mode local

Unified pipeline with imported targets (skips probe):

    casm run unified --config scopes/scope.yaml --targets-file targets/target02-harness.json --sarif-mode local

Detailed unified report (includes per-endpoint findings):

    casm run unified --config scopes/scope.yaml --targets-file targets/target02-harness.json --sarif-mode local --detailed

Diff two runs (SARIF):

    casm diff --old runs/<engagement>/<run_id>/results.sarif --new runs/<engagement>/<run_id>/results.sarif

Include unchanged findings in the diff report:

    casm diff --old runs/<engagement>/<run_id>/results.sarif --new runs/<engagement>/<run_id>/results.sarif --include-unchanged

Targets file format (JSON harness):

    {
      "targets": [
        { "url": "https://127.0.0.1:8443/health", "method": "HEAD" },
        { "url": "https://localhost:8444/headers/none" }
      ]
    }

Outputs are written to `runs/<engagement>/<run_id>/` by default and include `targets.jsonl`, `evidence.jsonl`, `results.sarif`, and `report.md`.

Evidence viewer:

    casm evidence --path runs/<engagement>/<run_id>/evidence.jsonl --type http_response --tool http_verify --limit 20

Whole-line search (default contains scope):

    casm evidence --path runs/<engagement>/<run_id>/evidence.jsonl --contains localhost:8444

Field-limited search (error scope only):

    casm evidence --path runs/<engagement>/<run_id>/evidence.jsonl --contains "tls:" --contains-scope error

Show only today's http errors:

    casm evidence --path runs/<engagement>/<run_id>/evidence.jsonl --type http_error --since 2026-02-01T00:00:00Z

Show a narrow window around an incident:

    casm evidence --path runs/<engagement>/<run_id>/evidence.jsonl --since 2026-02-01T17:34:00Z --until 2026-02-01T17:36:00Z

Timestamps follow RFC3339; if no timezone is provided, UTC is assumed.

---

## Quick Start

```bash
# Install from source checkout
pip install -e .

# Scan your infrastructure
casm run unified --config scopes/scope.yaml --targets-file targets/target-harness.example.json

# Compare to previous run
casm diff --old runs/baseline/results.sarif --new runs/current/results.sarif
```

## Evidence model (what you can rely on)

Evidence is written as JSONL (one JSON object per line). Key fields include:
- `engagement_id`, `run_id`
- `tool_name`, `tool_version`
- `type` (e.g., `tcp_connect`, `run_result`)
- `target` (e.g., `example.com:443`)
- `timestamp` (UTC)
- `status` (`success|timeout|error|blocked`)
- `duration_ms`
- `data` (structured, redacted)
- `data.canonical_url` (stable, normalized URL for comparisons)
- `data.finding_fingerprints` (stable identifiers for findings tied to the event)
- `schema_version` (semantic version for evidence schema)
- SARIF `properties.severity` is set per rule, and SARIF `level` maps to that severity
- SARIF includes `properties.schema_version` at the top level and per run

A centralized redaction step is applied to evidence data and persisted tool logs to scrub obvious secrets.

---

## Reporting & exports

- The Markdown report is dual-audience:
  - Executive Summary (metrics + top recommendation)
  - Technical Summary, Scope & Method, Limitations, Assets Observed, Findings, Telemetry
- Findings are grounded in evidence IDs for traceability.
- SARIF 2.1.0 export includes normalized findings only (not telemetry-only events).

Migration:

    casm migrate --input runs/<engagement>/<run_id> --out runs/<engagement>/<run_id>-migrated

---

## Configuration

Environment defaults are documented in `.env.example`.

Key scope fields (see `scopes/scope.yaml`):
- `seed_targets`: initial hostnames
- `allowed_domains`, `allowed_ips`
- `allowed_ports`, `allowed_protocols`
- `max_rate`, `max_concurrency`
- `per_attempt_timeout_ms`, `tool_timeout_ms`
- `active_allowed`, `auth_allowed`

---

## Development notes

For development workflow, see CONTRIBUTING.md.

## Versioning

Release versioning is tag-driven (`vMAJOR.MINOR.PATCH`).

---

## License

CASM is licensed under the GNU Affero General Public License Version 3 (AGPLv3).

This means:
- ✅ Free to use and modify
- ✅ Free for internal use
- ✅ Must share modifications if you run CASM as a network service
- ✅ Commercial licenses available for proprietary use

For commercial licensing inquiries: contact@g2cv.com

Copyright (C) 2026 G2CV Solutions
