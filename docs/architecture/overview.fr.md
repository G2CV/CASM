# Vue d'ensemble de l'architecture

> **Prérequis**
> - Connaître les bases Python et Go.
> - Comprendre JSON, CLI et subprocess.

## Diagramme système

CASM suit un modèle "Brain / Hands":

- **Brain (Python)**: politique, orchestration, normalisation de preuves, génération de rapports.
- **Hands (Go)**: exécution réseau (TCP, HTTP, DNS) avec sorties JSON déterministes.

## Brain vs Hands

- Python decide *quoi* faire et *si c'est autorisé* (`ScopeGuard`).
- Go exécute les actions réseau de façon performante.
- Les décisions métier restent côté Python.

Exemple concret:

1. Python construit une requête outil (`ToolRequest`).
2. Go exécute et retourne constats/preuves.
3. Python écrit les artefacts et construit SARIF/rapport.

## Mécanisme IPC

Le pont Python/Go utilise un seul modèle:

- `subprocess.run` + JSON sur STDIN/STDOUT

Contrats:

- Python -> Go: `contracts/schemas/*_request.schema.json`
- Go -> Python: `contracts/schemas/*_response.schema.json`
- Télémétrie: `evidence.jsonl`, `results.sarif`

## Modèle de concurrence

- Python: orchestration majoritairement mono-processus + un processus outil par étape.
- Go:
  - `probe`: boucle séquentielle cadencée
  - `http_verify`: worker pool
  - `dns_enum`: worker pool

Primitives Go courantes: `WaitGroup`, `Mutex`, `atomic`, channels.

## Artefacts runtime

Chaque exécution écrit sous `runs/<engagement_id>/<run_id>/`:

- `targets.jsonl`
- `evidence.jsonl`
- `results.sarif`
- `report.md`
- `report.pdf` (optionnel)
