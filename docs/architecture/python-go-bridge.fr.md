# Contrat d'interface Python-Go

> **Prérequis**
> - Comprendre les bases JSON Schema.

## Résumé du contrat

Le bridge Python/Go repose sur un contrat JSON strict sur stdio.

- Probe:
  - requête: `contracts/schemas/tool_request.schema.json`
  - réponse: `contracts/schemas/tool_response.schema.json`
- HTTP verify:
  - requête: `contracts/schemas/http_verify_request.schema.json`
  - réponse: `contracts/schemas/http_verify_response.schema.json`
- DNS enum:
  - requête: `contracts/schemas/dns_enum_request.schema.json`
  - réponse: `contracts/schemas/dns_enum_response.schema.json`

## Encodage des messages

- objets JSON UTF-8
- une requête sur stdin
- une réponse sur stdout
- télémétrie complementaire en fichiers (`evidence.jsonl`, `results.sarif`)

## Sémantique succes/échec

| Condition | Surface Python | Signification |
|---|---|---|
| timeout subprocess | `blocked_reason=tool_timeout` | depassement du timeout |
| exit non-zero | `blocked_reason=tool_error` | échec process outil |
| JSON stdout invalide | `blocked_reason=invalid_tool_output` | violation du contrat |
| blocage de politique | `blocked_reason=<reason>` | exécution interdite |
| `ok=true` | succès normal | constats/preuves valides |

Codes frequents:

- `aborted`, `dry_run`, `tool_not_found`, `tool_timeout`, `tool_error`
- `invalid_tool_output`, `domain_out_of_scope`, `ip_out_of_scope`
- `port_not_allowed`, `protocol_not_allowed`, `rate_limit_exceeded`, `concurrency_limit_exceeded`

## Panic/crash

- panic Go + exit non-zero -> `tool_error`
- sortie partielle/malformee -> `invalid_tool_output`

## FFI / C bindings

- Aucun dans ce repo.
- Integration basee process (binaires CLI), pas shared library.
