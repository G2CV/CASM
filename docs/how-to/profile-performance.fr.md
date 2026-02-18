# Comment profiler les performances

> **Prérequis**
> - Pouvoir exécuter des scans locaux sur des cibles contrôlées.

## Timing Python (orchestration)

Utiliser les métriques de run et le wall-clock:

```bash
time casm run unified --config scopes/scope.yaml --dry-run=false
```

Inspecter les champs `duration_ms` dans `evidence.jsonl`.

## Profiling CPU/Memoire côté Go

Pour un nouvel outil, ajouter des hooks `pprof` dans des builds non production.

Harness recommande:

1. Set de cibles fixe
2. timeout/rate/concurrency fixes
3. N runs repétés
4. comparer mediane et p95

## Heuristiques de tuning rate/concurrency

- Augmenter `max_concurrency` seulement si timeout/error restent stables.
- Règler `tool_timeout_ms` au-dessus de la duree totale estimee.
- Garder `max_rate` sous les limites des systemes cibles.

Attention: forte concurrence + scope large peut créer de la charge non voulue, même en mode safe-check.
