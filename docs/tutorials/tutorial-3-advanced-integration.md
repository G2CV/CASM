# Tutorial 3: Advanced Integration (45 min)

> **Prerequisites**
> - Completed Tutorial 2
> - Basic CI familiarity

## Scenario

Integrate CASM into a CI pipeline using SARIF outputs and periodic PDF executive reporting.

## Step 1: Run unified scan in CI-friendly mode

```bash
casm run unified --config scopes/scope.yaml --sarif-mode github --dry-run=false --enable-dns-enum
```

This emits per-tool SARIF files:

- `results-probe.sarif`
- `results-http-verify.sarif`
- `results-dns-enum.sarif` (if DNS enabled)

## Step 2: Upload SARIF to your CI security dashboard

Use your CI platform SARIF uploader (GitHub Code Scanning or equivalent).

## Step 3: Generate PDF for stakeholders

```bash
casm run unified --config scopes/scope.yaml --format markdown,sarif,pdf --dry-run=false
```

For French stakeholder reports:

```bash
casm run unified --config scopes/scope.yaml --format markdown,pdf --report-lang fr --dry-run=false
```

## Step 4: Migrate historical runs if schema changes

```bash
casm migrate --input runs/<engagement>/<old_run> --out runs/<engagement>/<old_run>-migrated
```

## Step 5: Build an automated regression gate

Use `casm diff` output to fail build when critical/high findings are added.

Example pseudo-flow:

1. Download baseline SARIF.
2. Run scan.
3. Run `casm diff`.
4. Parse "Added" section; fail if severity is `critical` or `high`.

⚠️ Warning: Ensure CI uses authorized target scopes only. Never scan assets without explicit permission.
