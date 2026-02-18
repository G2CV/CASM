# Annexe: matrice des signatures de fonctions

Cette annexe fournit une vue stricte, fonction par fonction, des contrats Python de production.

## Comment là lire

- `Required` indique l'absence de valeur par défaut.
- `Errors` liste uniquement les `raise` explicites du corps de fonction.
- Les exceptions runtime/dépendances peuvent exister même si `Errors` est vide.
- Là ligne `Source` permet d'ouvrir rapidement l'implementation.

La structure est volontairement mecanique pour faciliter la comparaison entre fonctions.

Version détaillée: `reference/function-signature-matrix.md`
