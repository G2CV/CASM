# Tutoriel 3: Intégration avancée (45 min)

> **Prérequis**
> - Avoir terminé le Tutoriel 2
> - Connaissances de base en CI

## Scénario

Intégrer CASM dans un pipeline CI avec sorties SARIF et génération PDF périodique pour les parties prenantes.

## Étape 1: lancer un scan unified en mode CI

```bash
casm run unified --config scopes/scope.yaml --sarif-mode github --dry-run=false --enable-dns-enum
```

Cette commande produit des SARIF par outil:

- `results-probe.sarif`
- `results-http-verify.sarif`
- `results-dns-enum.sarif` (si DNS active)

## Étape 2: envoyer SARIF vers votre tableau de bord sécurité CI

Utilisez l'uploader SARIF de votre plateforme CI (GitHub Code Scanning ou équivalent).

## Étape 3: générer un PDF pour les parties prenantes

```bash
casm run unified --config scopes/scope.yaml --format markdown,sarif,pdf --dry-run=false
```

Pour un rapport en français:

```bash
casm run unified --config scopes/scope.yaml --format markdown,pdf --report-lang fr --dry-run=false
```

## Étape 4: migrer les exécutions historiques en cas de changement de schéma

```bash
casm migrate --input runs/<engagement>/<old_run> --out runs/<engagement>/<old_run>-migrated
```

## Étape 5: mettre en place une barrière de régression

Utilisez la sortie de `casm diff` pour faire échouer le build quand des constats `critical`/`high` sont ajoutés.

Pseudo-flux:

1. Télécharger la SARIF de référence.
2. Lancer le scan.
3. Lancer `casm diff`.
4. Analyser la section "Added"; échouer si la sévérité est `critical` ou `high`.

Attention: en CI, utilisez uniquement des scopes explicitement autorisés. Ne scannez jamais des actifs sans permission.
