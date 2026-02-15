# Security Model and Threat Considerations

## Core Security Controls

- Authorization-first scope model (domains/IPs/ports/protocols).
- Default dry-run behavior.
- Deterministic blocking reason codes.
- Rate and concurrency guardrails.
- Redaction before persistence.

## Threats and Mitigations

| Threat | Mitigation |
|---|---|
| Accidental out-of-scope scan | `ScopeGuard` checks before tool invocation |
| Excessive scanning load | `max_rate`, `max_concurrency`, tool timeout limits |
| Secret leakage in artifacts | `redaction.py` + redacted tool log persistence |
| Non-deterministic false diffs | canonical URL/fingerprint strategies |
| Tool crash propagation | adapter maps failures to blocked reasons |

## Dangerous Operations

⚠️ Warning: Enabling `http_verify_tls_insecure_skip_verify` disables certificate validation and should only be used for controlled lab environments.

⚠️ Warning: `check_zone_transfer` in DNS enumeration can trigger high-signal network behavior; use only with explicit authorization.
