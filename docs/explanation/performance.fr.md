# Performance et benchmarks

> **Prérequis**
> - Cibles de test contrôlées
> - Possibilite de lancer plusieurs iterations

## Caracteristiques par étape

- Probe: `O(targets * ports)`
- HTTP verify: `O(targets * redirects)` + checks headers/TLS
- DNS enum: `O(domains * record_types * candidates)`
- Merge evidence/report: `O(events log events)` (tri)

## Bottlenecks

- Latence réseau et handshakes TLS dominent souvent le runtime.
- DNS actif scale avec la taille de wordlist.
- Cout serialisation/IO fichiers augmente avec le volume d'evidence.

## Harness benchmark recommande

Lancer 10 scans avec inputs fixes et mesurer mediane/p95:

```bash
for i in {1..10}; do
  /usr/bin/time -f "%e" casm run unified --config scopes/scope.yaml --dry-run=false >/tmp/casm.$i.log 2>&1
done
```

## Template de tendance

Le graphe Mermaid de la page EN peut être reutilise avec vos valeurs mesurees.

Astuce: garder `max_rate` et `max_concurrency` constants pour comparer des exécutions.
