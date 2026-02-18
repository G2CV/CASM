# Tutoriel 2: Cas d'usage réel (20 min)

> **Prérequis**
> - Avoir terminé le Tutoriel 1

## Scénario

Vous voulez surveiller un ensemble de cibles connu et comparer les nouveaux constats avec une référence.

## Étape 1: créer une référence

```bash
casm run unified --config scopes/scope.yaml --sarif-mode local --dry-run=false
```

Conservez le chemin SARIF de référence affiché par la CLI.

## Étape 2: relancer un scan après changement

```bash
casm run unified --config scopes/scope.yaml --sarif-mode local --dry-run=false
```

## Étape 3: comparer la référence et le scan courant

```bash
casm diff --old runs/<baseline>/results.sarif --new runs/<current>/results.sarif
```

## Étape 4: inspecter les preuves

```bash
casm evidence --path runs/<current>/evidence.jsonl --type http_response --limit 20
```

Points à vérifier:

- Nouvelles valeurs `finding_fingerprint`
- Nouveaux domaines/sous-domaines dans les événements DNS
- Observations HTTP et motifs d'en-têtes manquants

Astuce: gardez chaque dossier d'exécution immuable; utilisez `diff` plutôt que modifier l'historique.
