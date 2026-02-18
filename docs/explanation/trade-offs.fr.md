# Compromis et alternatives

## Approches choisies vs rejetées

| Sujet | Choisi | Rejeté | Raison |
|---|---|---|---|
| Intégration runtime | subprocess + JSON | gRPC ou cgo/FFI | couplage faible, déploiement/debug plus simples |
| Stockage des preuves | filesystem JSONL | modèle DB-first | meilleure portabilité et export audit |
| Enforcement de périmètre | guard Python central + checks Go | checks locaux outil seulement | cohérence de politique + defense in depth |
| Reporting | Markdown + SARIF + PDF optionnel | format unique | utile pour audiences exécutive et automation |

## Compromis acceptés

- Surcoût de sérialisation JSON à chaque appel outil.
- Validation dupliquée Python + Go pour la sécurité.
- Dossiers d'artefacts volumineux -> nécessite une politique de rétention.

## Pourquoi pas REST entre brain et hands?

- Les subprocess locaux évitent la gestion d'un service.
- Aucun port réseau local à exposer.
- Moins de composants pour CI et exécution offline.
