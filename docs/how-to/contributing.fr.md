# Guide de contribution

## Principes

- Garder l'enforcement de périmètre centralisé (`ScopeGuard`).
- Garder l'exécution outil derrière des interfaces adapter.
- Garder des sorties déterministes (tri/fingerprints stables).
- Garder des tests offline-first et reproductibles.

## Flux de contribution

1. Créer une branche ciblée.
2. Faire un changement petit et cohérent.
3. Ajouter des tests pour tout changement de comportement.
4. Exécuter:

```bash
make test
```

5. Mettre à jour la doc `docs/` si comportement/contrat modifié.

## Qualité des commits

- Expliquer le **pourquoi** dans le message.
- Synchroniser schéma et fixtures.
- Ne pas committer de secrets ni credentials d'environnement.

## Checklist cross-language

- [ ] Payload Python mis à jour
- [ ] Struct Go mis à jour
- [ ] Schéma JSON mis à jour
- [ ] Fixtures mises à jour
- [ ] Tests mis à jour des deux côtés
- [ ] Documentation de référence mise à jour
