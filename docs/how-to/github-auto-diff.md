# GitHub Auto-Diff Bot

Use the CASM GitHub Action to run unified scans, diff against a cached baseline SARIF, and post evidence-first comments to PRs or a baseline issue.

Repository example: `.github/workflows/casm-auto-diff-example.yml`.

## Example Workflow

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

## Inputs

- `scope-path` (required): CASM scope file.
- `targets-file` (optional): explicit targets JSON file.
- `baseline-path` (optional): baseline SARIF path.
- `post-mode`: `none`, `auto`, `issue`, or `pr`.
- `pr-number` / `issue-number`: explicit publish target.
- `issue-title`: issue title for auto-created baseline issue.
- `issue-labels`: comma-separated labels for baseline issue creation.
- `max-findings`: max added/removed findings listed in the comment.

## Outputs

- `added-count`, `removed-count`, `unchanged-count`
- `has-baseline`, `has-changes`
- `published`, `target-kind`, `target-number`, `post-skipped-reason`
- `evidence-path`, `sarif-path`, `report-path`, `summary-path`, `baseline-path`

## Notes

- The action updates `baseline-path` each run; cache or commit that path to persist baseline between runs.
- `post-mode=auto` posts to PR when `pr-number` is set, otherwise to an issue.
- For strict pipelines, set `fail-on-publish-error: true` to fail the job when comment publishing fails.
