# Référence API Go (annotée)

Cette page cible les commandes Go sous `hands/cmd/*`.

## Outils principaux

- `probe`: vérification TCP sur host:port
- `http_verify`: checks HTTP/TLS et headers de sécurité
- `dns_enum`: découverte DNS passive/active

## Règles de contrat

- entree JSON unique sur stdin
- sortie JSON unique sur stdout
- télémétrie ecrite dans des artefacts (`evidence.jsonl`, `results.sarif`)

## Recommandations de modification

- conserver une sortie détérministe
- preserver reason codes existants
- mettre à jour schémas + fixtures + tests en même temps

Version détaillée: `reference/go-api.md`
