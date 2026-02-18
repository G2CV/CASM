# Comment éténdre l'interface Python-Go

## Étapes

1. Mettre à jour le schéma JSON dans `contracts/schemas/`.
2. Mettre à jour les structs Go request/response.
3. Mettre à jour le payload builder Python et le parser adapter.
4. Ajouter les fixtures dans `contracts/fixtures/`.
5. Ajouter/adapter les tests des deux côtés.

## Règle de compatibilité backward

- Preferer des champs additifs.
- Defauts safe en Go (`defaults`/`applyDefaults`) et en Python.
- Preserver les reason codes existants.

## Strategie de validation

- Valider la forme schéma dans les tests.
- Executer une commande CLI end-to-end pour vérifier la compatibilité de serialisation.

```bash
make test
```
