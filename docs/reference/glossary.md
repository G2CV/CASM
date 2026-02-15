# Glossary

- **CASM**: Continuous Attack Surface Monitoring.
- **Engagement**: A logically isolated scan context identified by `engagement_id`.
- **Run**: One execution instance identified by `run_id`.
- **Scope**: Explicit allowlist policy for domains, IP ranges, ports, and protocols.
- **ScopeGuard**: Python policy checker that enforces scope before execution.
- **Evidence**: JSONL event records that capture raw scan telemetry and context.
- **Finding**: Normalized security issue derived from evidence/observations.
- **SARIF**: Static Analysis Results Interchange Format used for CI integration.
- **Fingerprint**: Stable hash identifying semantically identical findings across runs.
- **Blocked reason**: Deterministic code describing why execution was prevented/failed.
- **Dry run**: Policy-only path that avoids active network operations.
- **Probe**: Go TCP connect checker tool.
- **HTTP Verify**: Go HTTP/TLS/header verification tool.
- **DNS Enum**: Go passive+active DNS enumeration tool.
- **Unified run**: Orchestrated pipeline combining probe, optional DNS, and HTTP verification.
