# Comment ajouter un nouveau module Python

## Objectif

Ajouter de la logique `brain` sans casser les frontières d'architecture.

## Étapes

1. Choisir le package:
   - `brain/core` pour la logique métier
   - `brain/adapters` pour les E/S et l'intégration
   - `brain/ports` pour les interfaces/protocoles
2. Ajouter les dataclasses/contrats partagés dans `brain/core/models.py` si nécessaire.
3. Garder les effets de bord dans les adapters, pas dans le core.
4. Ajouter les tests sous `brain/tests/`.
5. Exécuter:

```bash
python -m pytest brain/tests
```

## Checklist module

- [ ] Annotations de type présentes
- [ ] Ordre de sortie déterministe si pertinent
- [ ] Rédaction appliquée avant persistance
- [ ] ScopeGuard appliqué sur les chemins réseau
