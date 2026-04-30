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
  notify
    test
  evidence
  migrate
  diff
  alert
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
| `--alert-on-diff` | flag | non | false |
| `--baseline-sarif` | path | non | auto-detect run précédente |
| `--alert-tool` | string | non | `http_verify` |
| `--alert-dry-run` | flag | non | false |
| `--alert-min-severity` | enum | non | scope/défaut |
| `--alert-rule-id` | string répétable | non | none |
| `--alert-uri-regex` | regex | non | none |
| `--alert-cooldown-minutes` | int | non | scope/défaut |
| `--alert-max-events` | int | non | scope/défaut |
| `--alert-state-path` | path | non | scope/défaut |
| `--alert-only-added` | flag | non | false |
| `--alert-only-removed` | flag | non | false |

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

## `casm alert`

- `--config`, `--old`, `--new` obligatoires
- `--tool` par défaut `http_verify`
- `--min-severity` optionnel: `critical|high|medium|low|info|unknown`
- `--rule-id` optionnel, répétable
- `--uri-regex` optionnel
- `--cooldown-minutes` optionnel (fenêtre anti-doublon)
- `--max-events` optionnel (limite de publication)
- `--state-path` optionnel (fichier d'état du cooldown)
- `--only-added` ou `--only-removed` optionnels
- `--dry-run` optionnel (évaluation sans publication)

Exemple:

```bash
casm alert \
  --config scopes/scope.yaml \
  --old runs/eng/baseline/results.sarif \
  --new runs/eng/current/results.sarif \
  --min-severity medium \
  --cooldown-minutes 60
```

## `casm notify test`

Envoie un événement synthétique via les publishers/routes de notification configurés.

| Option | Type | Requis | Defaut |
|---|---|---|---|
| `--config` | path | oui | - |
| `--event-type` | string | non | `notification_test` |
| `--severity` | enum | non | `info` |
| `--rule-id` | string | non | `NOTIFICATION_TEST` |
| `--uri` | string | non | `casm://notification-test` |
| `--message` | string | non | `CASM notification test event.` |
| `--dry-run` | flag | non | false |
| `--json` | flag | non | false, affiche l'événement JSON au lieu du texte de statut |

Exemple:

```bash
casm notify test \
  --config scopes/scope.yaml \
  --event-type finding_added \
  --severity medium \
  --rule-id MISSING_CSP \
  --uri https://example.com/
```
