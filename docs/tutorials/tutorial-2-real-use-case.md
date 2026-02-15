# Tutorial 2: Real Use Case (20 min)

> **Prerequisites**
> - Completed Tutorial 1

## Scenario

You want to monitor a known target set and compare new findings with a baseline.

## Step 1: Create baseline run

```bash
casm run unified --config scopes/scope.yaml --sarif-mode local --dry-run=false
```

Save the baseline SARIF path printed by CLI.

## Step 2: Run a second scan after change

```bash
casm run unified --config scopes/scope.yaml --sarif-mode local --dry-run=false
```

## Step 3: Compare baseline vs current

```bash
casm diff --old runs/<baseline>/results.sarif --new runs/<current>/results.sarif
```

## Step 4: Inspect evidence

```bash
casm evidence --path runs/<current>/evidence.jsonl --type http_response --limit 20
```

What to look for:

- New `finding_fingerprint` values
- New domains/subdomains in DNS events
- HTTP observations and missing header patterns

💡 Tip: Keep each run directory immutable; use `diff` instead of editing historical outputs.
