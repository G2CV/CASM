# Décisions de conception

## Pourquoi Python pour la logique et Go pour l'exécution?

- Python est très efficace pour l'orchestration, la transformation schéma/data et la composition de rapports.
- Go est très adapté à l'exécution réseau prévisible, la concurrence légère et la distribution en binaire.

Ce découpage garde la politique lisible et les E/S bas niveau performantes.

## Pourquoi une frontière process plutôt que des bindings in-process?

- Meilleure isolation: un crash Go ne corrompt pas l'état Python.
- Contrats JSON versionnés et auditables.
- Tests de contrat simples via fixtures.

## Pourquoi une architecture orientée preuves (evidence-first)?

- Les rapports sont des vues dérivées.
- JSONL est simple pour machine + stream/append.
- Base solide pour le diffing et la traçabilité conformité.

## Pourquoi canonicalisation/fingerprints stables?

- Nécessaires pour des comparaisons de référence fiables.
- Évitent le bruit lié à l'ordre ou au formatage des URL.
