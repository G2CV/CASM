# Flux de données et séquences

> **Prérequis**
> - Lire d'abord `docs/architecture/overview.fr.md`.

## Flux unifié de bout en bout

Séquence simplifiée:

1. CLI charge le périmètre.
2. `run_unified(...)` orchestre DNS/probe/import selon options.
3. `http_verify` exécute les vérifications HTTP.
4. Python fusionne preuves + constats.
5. CASM écrit `targets.jsonl`, `evidence.jsonl`, `results.sarif`, `report.md`.

Commande type:

```bash
casm run unified --config scopes/scope.yaml
```

## Flux probe uniquement

1. `casm run probe --scope ...`
2. Orchestrator -> ToolGatewayAdapter
3. Vérifications de politique/rate/dry-run
4. Appel du binaire Go `probe`
5. Écriture des artefacts

## Propagation des erreurs

- timeout process -> `blocked_reason=tool_timeout`
- exit non-zero -> `blocked_reason=tool_error`
- JSON invalide -> `blocked_reason=invalid_tool_output`
- blocage de politique -> `blocked_reason=<reason>`

## Cycle de vie des données

1. Arguments CLI
2. Parsing du périmètre -> dataclass `Scope`
3. Enforcement de la politique
4. Émission des sorties outil
5. Normalisation Python (schéma, URL canoniques, IDs stables)
6. Consommation des artefacts via:
   - `casm evidence`
   - `casm diff`
   - génération PDF

Astuce: considérez `evidence.jsonl` comme source de vérité. Les rapports sont des vues dérivées.
