# Bot GitHub Auto-Diff

Utilisez l'action GitHub CASM pour executer des scans unifies, comparer avec un baseline SARIF mis en cache, et publier des commentaires evidence-first directement sur les PR ou sur une issue baseline.

Exemple dans le repo: `.github/workflows/casm-auto-diff-example.yml`.

## Exemple de workflow

```yaml
name: CASM Auto-Diff

on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:
  pull_request:
    branches: [main]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  casm-auto-diff:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Restore baseline cache
        uses: actions/cache/restore@v4
        with:
          path: .casm/baseline
          key: casm-baseline-${{ github.ref_name }}-${{ github.run_id }}
          restore-keys: |
            casm-baseline-${{ github.ref_name }}-

      - name: Run CASM Auto-Diff
        id: casm
        uses: g2cv/casm@v1
        with:
          scope-path: scopes/scope.yaml
          targets-file: targets/targets.json
          baseline-path: .casm/baseline/results.sarif
          post-mode: auto
          pr-number: ${{ github.event.pull_request.number }}
          issue-title: CASM Security Baseline
          post-on-no-change: false

      - name: Upload run artifacts
        uses: actions/upload-artifact@v4
        with:
          name: casm-auto-diff-${{ github.run_id }}
          path: |
            runs/current/evidence.jsonl
            runs/current/results.sarif
            runs/current/report.md
            runs/current/auto-diff.md
            runs/current/auto-diff.json

      - name: Save baseline cache
        uses: actions/cache/save@v4
        with:
          path: .casm/baseline
          key: casm-baseline-${{ github.ref_name }}-${{ github.run_id }}
```

## Entrees

- `scope-path` (obligatoire): fichier scope CASM.
- `targets-file` (optionnel): fichier JSON de cibles explicites.
- `baseline-path` (optionnel): chemin du SARIF baseline.
- `post-mode`: `none`, `auto`, `issue` ou `pr`.
- `pr-number` / `issue-number`: cible explicite de publication.
- `issue-title`: titre de l'issue baseline creee automatiquement.
- `issue-labels`: labels separes par des virgules lors de la creation de l'issue baseline.
- `max-findings`: nombre max de findings ajoutes/supprimes affiches dans le commentaire.

## Sorties

- `added-count`, `removed-count`, `unchanged-count`
- `has-baseline`, `has-changes`
- `published`, `target-kind`, `target-number`, `post-skipped-reason`
- `evidence-path`, `sarif-path`, `report-path`, `summary-path`, `baseline-path`

## Notes

- L'action met a jour `baseline-path` a chaque run; utilisez un cache ou un commit pour conserver ce baseline entre les executions.
- `post-mode=auto` publie sur la PR si `pr-number` est defini, sinon sur une issue.
- Pour un pipeline strict, definissez `fail-on-publish-error: true` pour echouer le job si la publication du commentaire echoue.
