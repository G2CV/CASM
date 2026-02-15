# CASM Documentation

CASM (Continuous Attack Surface Monitoring) is a dual-runtime security system:

- Python (`brain/`) orchestrates policy, workflows, evidence normalization, and report generation.
- Go (`hands/`) executes network operations (TCP probe, HTTP verification, DNS enumeration) safely and deterministically.

This documentation set is organized for MkDocs and for readers who are new to the project.

## Documentation Map

- Architecture
  - `docs/architecture/overview.md`
  - `docs/architecture/data-flow.md`
  - `docs/architecture/python-go-bridge.md`
- Tutorials
  - `docs/tutorials/setup-for-beginners.md`
  - `docs/tutorials/tutorial-1-hello-world.md`
  - `docs/tutorials/tutorial-2-real-use-case.md`
  - `docs/tutorials/tutorial-3-advanced-integration.md`
- How-to guides
  - `docs/how-to/add-python-module.md`
  - `docs/how-to/add-go-package.md`
  - `docs/how-to/extend-bridge.md`
  - `docs/how-to/debug-cross-language.md`
  - `docs/how-to/testing.md`
  - `docs/how-to/profile-performance.md`
  - `docs/how-to/contributing.md`
- Reference
  - `docs/reference/component-inventory.md`
  - `docs/reference/data-structures.md`
  - `docs/reference/python-api.md`
  - `docs/reference/go-api.md`
  - `docs/reference/function-catalog.md`
  - `docs/reference/cli.md`
  - `docs/reference/configuration.md`
  - `docs/reference/glossary.md`
- Explanation
  - `docs/explanation/design-decisions.md`
  - `docs/explanation/trade-offs.md`
  - `docs/explanation/security-model.md`
  - `docs/explanation/performance.md`

## Reader Path

1. Start with architecture files.
2. Run Tutorial 1, then Tutorial 2.
3. Use reference docs during implementation.
4. Use explanation docs for rationale and trade-offs.

## Project Facts

- Python requirement: `>=3.11` (`pyproject.toml`)
- Go requirement: `1.21` (`hands/go.mod`)
- Core output artifacts:
  - `targets.jsonl`
  - `evidence.jsonl`
  - `results.sarif`
  - `report.md`
  - `report.pdf` (optional)

> 💡 Tip: For first-time setup, jump directly to `docs/tutorials/tutorial-1-hello-world.md`.
