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
