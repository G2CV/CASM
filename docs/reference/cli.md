# CLI Reference

Executable entrypoint:

- `casm` (from `pyproject.toml` script)
- wrapper file: `casm`

## Command Tree

```text
casm
  run
    probe
    http-verify
    unified
    dns-enum
  evidence
  migrate
  diff
  alert
```

## `casm run probe`

| Flag | Type | Required | Default |
|---|---|---|---|
| `--scope` | path | yes | - |
| `--tool-path` | path | no | `hands/bin/probe` |
| `--dry-run[=bool]` | bool | no | `DRY_RUN` env |

## `casm run http-verify`

| Flag | Type | Required | Default |
|---|---|---|---|
| `--scope` | path | yes | - |
| `--tool-path` | path | no | `hands/bin/http_verify` |
| `--dry-run[=bool]` | bool | no | `DRY_RUN` env |

## `casm run unified`

| Flag | Type | Required | Default |
|---|---|---|---|
| `--config` | path | yes | - |
| `--out` | path | no | auto run dir |
| `--sarif-mode` | enum | no | `local` |
| `--probe-tool-path` | path | no | `hands/bin/probe` |
| `--http-tool-path` | path | no | `hands/bin/http_verify` |
| `--targets-file` | path | no | none |
| `--dry-run[=bool]` | bool | no | `DRY_RUN` env |
| `--enable-dns-enum` | flag | no | false |
| `--dns-tool-path` | path | no | `hands/bin/dns_enum` |
| `--dns-wordlist` | path | no | scope/default |
| `--detailed` | flag | no | false |
| `--format` | csv/all | no | `all` |
| `--report-lang` | enum (`en`,`fr`) | no | `en` |
| `--alert-on-diff` | flag | no | false |
| `--baseline-sarif` | path | no | auto-detect previous run |
| `--alert-tool` | string | no | `http_verify` |
| `--alert-dry-run` | flag | no | false |
| `--alert-min-severity` | enum | no | from scope/default |
| `--alert-rule-id` | repeatable str | no | none |
| `--alert-uri-regex` | regex | no | none |
| `--alert-cooldown-minutes` | int | no | from scope/default |
| `--alert-max-events` | int | no | from scope/default |
| `--alert-state-path` | path | no | from scope/default |
| `--alert-only-added` | flag | no | false |
| `--alert-only-removed` | flag | no | false |

Language examples:

```bash
# French markdown + PDF report output
casm run unified --config scopes/scope.yaml --format markdown,pdf --report-lang fr --dry-run=false

# English (default)
casm run unified --config scopes/scope.yaml --format markdown,pdf --report-lang en --dry-run=false
```

## `casm run dns-enum`

| Flag | Type | Required | Default |
|---|---|---|---|
| `--config` | path | yes | - |
| `--tool-path` | path | no | `hands/bin/dns_enum` |
| `--out` | path | no | auto run dir |
| `--domain` | repeatable str | no | none |
| `--domains-file` | path | no | none |
| `--wordlist` | path | no | scope/default |
| `--passive-only` | flag | no | false |
| `--rate-limit` | int | no | none |
| `--timeout` | int ms | no | none |
| `--max-depth` | int | no | none |
| `--record-types` | list[str] | no | none |
| `--dry-run[=bool]` | bool | no | `DRY_RUN` env |

## `casm evidence`

Key filters: `--type`, `--tool`, `--target-id`, `--contains`, `--since`, `--until`, `--limit`.

## `casm migrate`

- `--input` required
- `--out` optional (`<input>-migrated` default)
- `--strict` fail fast on invalid JSON

## `casm diff`

- `--old`, `--new` required
- `--tool` default `http_verify`
- `--include-unchanged` optional
- `--out` optional output file

## `casm alert`

- `--config`, `--old`, `--new` required
- `--tool` default `http_verify`
- `--min-severity` optional: `critical|high|medium|low|info|unknown`
- `--rule-id` optional repeatable allow-list
- `--uri-regex` optional URI filter
- `--cooldown-minutes` optional duplicate suppression window
- `--max-events` optional publish cap
- `--state-path` optional cooldown state file path
- `--only-added` or `--only-removed` optional event type scope
- `--dry-run` optional evaluation-only mode

Example:

```bash
casm alert \
  --config scopes/scope.yaml \
  --old runs/eng/baseline/results.sarif \
  --new runs/eng/current/results.sarif \
  --min-severity medium \
  --cooldown-minutes 60
```
