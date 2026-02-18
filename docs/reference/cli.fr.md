# Référence CLI

Points d'entree executables:

- `casm` (script defini dans `pyproject.toml`)
- fichier wrapper: `casm`

## Arborescence des commandes

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

| Option | Type | Requis | Defaut |
|---|---|---|---|
| `--scope` | path | oui | - |
| `--tool-path` | path | non | `hands/bin/probe` |
| `--dry-run[=bool]` | bool | non | env `DRY_RUN` |

## `casm run http-verify`

| Option | Type | Requis | Defaut |
|---|---|---|---|
| `--scope` | path | oui | - |
| `--tool-path` | path | non | `hands/bin/http_verify` |
| `--dry-run[=bool]` | bool | non | env `DRY_RUN` |

## `casm run unified`

| Option | Type | Requis | Defaut |
|---|---|---|---|
| `--config` | path | oui | - |
| `--out` | path | non | dossier de run auto |
| `--sarif-mode` | enum | non | `local` |
| `--probe-tool-path` | path | non | `hands/bin/probe` |
| `--http-tool-path` | path | non | `hands/bin/http_verify` |
| `--targets-file` | path | non | none |
| `--dry-run[=bool]` | bool | non | env `DRY_RUN` |
| `--enable-dns-enum` | flag | non | false |
| `--dns-tool-path` | path | non | `hands/bin/dns_enum` |
| `--dns-wordlist` | path | non | scope/default |
| `--detailed` | flag | non | false |
| `--format` | csv/all | non | `all` |
| `--report-lang` | enum (`en`,`fr`) | non | `en` |

Exemples de langue:

```bash
# Rapport markdown + PDF en francais
casm run unified --config scopes/scope.yaml --format markdown,pdf --report-lang fr --dry-run=false

# Anglais (défaut)
casm run unified --config scopes/scope.yaml --format markdown,pdf --report-lang en --dry-run=false
```

## `casm run dns-enum`

| Option | Type | Requis | Defaut |
|---|---|---|---|
| `--config` | path | oui | - |
| `--tool-path` | path | non | `hands/bin/dns_enum` |
| `--out` | path | non | dossier de run auto |
| `--domain` | string repetable | non | none |
| `--domains-file` | path | non | none |
| `--wordlist` | path | non | scope/default |
| `--passive-only` | flag | non | false |
| `--rate-limit` | int | non | none |
| `--timeout` | int ms | non | none |
| `--max-depth` | int | non | none |
| `--record-types` | list[str] | non | none |
| `--dry-run[=bool]` | bool | non | env `DRY_RUN` |

## `casm evidence`

Filtres principaux: `--type`, `--tool`, `--target-id`, `--contains`, `--since`, `--until`, `--limit`.

## `casm migrate`

- `--input` obligatoire
- `--out` optionnel (défaut: `<input>-migrated`)
- `--strict` echoue immediatement en cas de JSON invalide

## `casm diff`

- `--old`, `--new` obligatoires
- `--tool` par défaut `http_verify`
- `--include-unchanged` optionnel
- `--out` fichier de sortie optionnel
