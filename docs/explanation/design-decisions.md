# Design Decisions

## Why Python for Logic and Go for Execution?

- Python excels at orchestration, schema/data transformation, report composition, and developer velocity.
- Go excels at predictable network execution, lightweight concurrency, and single-binary tool distribution.

This split keeps high-level policy readable while keeping low-level IO efficient.

## Why Process Boundary Instead of In-Process Bindings?

- Simpler isolation model: a crashing Go tool does not corrupt Python state.
- Explicit versioned JSON contracts make behavior auditable.
- Easier to test tool contracts with fixtures.

## Why Evidence-First Architecture?

- Reports are derivable views.
- JSONL evidence is machine-friendly and append/stream friendly.
- Supports diffing and compliance traceability.

## Why Stable Canonicalization and Fingerprints?

- Needed for reliable baseline comparisons.
- Prevents noisy deltas from ordering or URL formatting differences.
