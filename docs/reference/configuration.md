# Configuration Reference

## Environment Variables

| Variable | Type | Default | Impact |
|---|---|---|---|
| `DRY_RUN` | bool | `true` | Default for `--dry-run` CLI option |
| `ABORT_RUN` | bool | `false` | Forces adapters to return `blocked_reason=aborted` |

## Scope File Schema (`scopes/scope.yaml`)

| Field | Type | Default | Validation / Constraints |
|---|---|---|---|
| `engagement_id` | string | required | non-empty |
| `allowed_domains` | list[string] | `[]` | fnmatch patterns |
| `allowed_subdomains` | list[string] | `[]` | merged into allowed patterns |
| `excluded_domains` | list[string] | `[]` | exclusion precedence over allowed |
| `allowed_ips` | list[string] | `[]` | valid CIDR strings |
| `allowed_ports` | list[int] | `[]` | 1..65535 expected |
| `allowed_protocols` | list[string] | `["tcp"]` | `tcp/http/https` in this codebase |
| `seed_targets` | list[string] | `[]` | hosts or URLs depending pipeline |
| `max_rate` | float | `1.0` | enforced by guard |
| `max_concurrency` | int | `1` | enforced by guard |
| `per_attempt_timeout_ms` | int | `750` | request timeout hints |
| `tool_timeout_ms` | int | `5000` | subprocess timeout |
| `http_verify_profile` | string | `baseline` | `baseline` or `web_hardening` |
| `http_verify_max_redirects` | int | `5` | >=0 |
| `http_verify_max_body_bytes` | int | `32768` | >=0 |
| `http_verify_tls_expiry_days` | int | `30` | >=1 |
| `http_verify_tls_ca_bundle_path` | string/null | null | optional CA override |
| `http_verify_tls_insecure_skip_verify` | bool | false | TLS validation bypass |
| `http_verify_tls_server_name` | string/null | null | SNI override |
| `http_verify_https_ports` | list[int] | `[443]` | ports forced to https |
| `inventory_resolve_ips` | bool | false | DNS resolve in inventory |
| `run_dir` | string/null | null | custom base run dir |
| `active_allowed` | bool | false | policy metadata |
| `auth_allowed` | bool | false | policy metadata |
| `time_window` | object/null | null | reserved metadata |
| `dns_enumeration` | object/null | null | DNS settings block |
| `pdf_branding` | object/null | null | PDF styling fields |
| `pdf_diff` | object/null | null | PDF diff section settings |

## DNS Enumeration Config Block

`dns_enumeration` fields include:

- `enabled`, `passive_only`, `passive_sources`, `wordlist_path`
- `nameserver` / `nameservers`
- `rate_limit`, `timeout`, `max_depth`, `max_consecutive_failures`
- `record_types`, `check_zone_transfer`, `detect_wildcard`
- `active_discovery.enabled|wordlist|rate_limit|timeout|max_depth|concurrency`

## Precedence Order

1. CLI explicit arguments (highest)
2. Environment defaults (used as parser defaults)
3. Scope file values
4. Hardcoded fallback defaults in Python/Go

Example:

- `--dry-run=false` overrides `DRY_RUN=true`.
- If scope omits `http_verify_max_redirects`, Python uses `5`.
- If request omits `limits.max_redirects`, Go `defaults()` sets `5`.
