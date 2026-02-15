# Go API Reference (Annotated)

This section documents all production Go functions in `hands/cmd/`.

## Shared Contract Types

### `probe/main.go`

- `ToolRequest`, `RateLimit`, `ProbeInput`, `Target`
- `ToolResponse`, `Evidence`, `Finding`

### `http_verify/main.go`

- `ToolRequest`, `TLSOptions`, `Scope`, `Target`, `Limits`, `EvidenceOut`, `SarifOut`
- `ToolResponse`, `Summary`, `ResultEntry`, `TLSInfo`, `Observation`, `EvidenceEvent`
- internal: `evidenceWriter`, `rateLimiter`, `sarifFinding`

### `dns_enum/*.go`

- `ToolRequest`, `DNSConfig`, `ActiveConfig`, `ToolResponse`
- `Discovery`, `QueryEvent`, `ErrorEvent`, `WildcardEvent`
- internal: `resultCollector`, `queryJob`, `DNSResolver`, `DNSAnswer`, `rateLimiter`, `axfrRecord`

## `hands/cmd/probe/main.go`

| Function | Signature | Purpose | Side Effects / Errors |
|---|---|---|---|
| `main` | `func main()` | parse request, perform TCP connect checks, emit response | network dials, stdout JSON |
| `writeError` | `func writeError(reason string)` | helper blocked response | stdout write |
| `writeResponse` | `func writeResponse(resp ToolResponse)` | encode JSON response | stdout write |

Edge cases:

- invalid request JSON -> `invalid_request`
- `DryRun` true -> `dry_run`
- `len(ports) > 100` -> `port_list_too_large`

## `hands/cmd/http_verify/main.go`

### Execution Core

| Function | Signature | Purpose |
|---|---|---|
| `main` | `func main()` | stdin/stdout bridge |
| `defaults` | `func defaults(req *ToolRequest)` | apply default limits/profile/https ports |
| `run` | `func run(req ToolRequest) ToolResponse` | worker pool execution and summary |
| `handleTarget` | `func handleTarget(...) ResultEntry` | per-target scope checks + attempt/response evidence |
| `executeRequest` | `func executeRequest(...) (ResultEntry, error)` | redirect loop + HEAD->GET fallback |
| `doOnce` | `func doOnce(...) (*http.Response, error)` | single request + GET body cap |

### Evidence and SARIF

| Function | Purpose |
|---|---|
| `newEvidenceWriter`, `(*evidenceWriter).write`, `(*evidenceWriter).close`, `nextID` | JSONL writer lifecycle and IDs |
| `eventFrom` | attach common event metadata |
| `writeSarif` | emit SARIF document |
| `buildFindings` | dedupe findings by rule + canonical endpoint |
| `sarifResults`, `sarifRules`, `validateSarifRules` | SARIF assembly/validation |
| `buildNotifications` | non-blocked runtime error notifications |

### Security Observation and Rule Mapping

- `headerObservations`
- `sarifForObservation`
- `observationToRule`
- `ruleDescription`, `ruleSeverity`, `sarifLevelForSeverity`, `allRuleIDs`
- content helpers: `isTextLikeMediaType`, `hasCharset`, `cspHasFrameAncestors`

### Scope/TLS/Canonicalization Helpers

- `checkScope`, `portFromURL`, `contains`, `containsInt`, `isIP`, `ipInScope`
- `buildTLSConfig`, `tlsErrorReason`, `tlsDetails`, `tlsVersion`, `tlsExpiresSoon`
- `canonicalizeAttemptURL`, `canonicalAttemptURL`, `canonicalEndpoint`, `canonicalizeRedirectChain`, `canonicalizeURL`
- fingerprint helpers: `findingFingerprint`, `fingerprintsForResult`, `finalScheme`

### Utility Helpers

- `buildClient`, `newRateLimiter`, `(*rateLimiter).wait`
- `buildResult`, `allowlistHeaders`
- `firstOrEmpty`, `firstString`, `firstRedirectChain`

Error behavior highlights:

- malformed input -> empty-ish response with tool metadata
- scope violation -> `http_blocked` evidence and `Error="blocked"`
- TLS validation failures normalized by `tlsErrorReason`
- redirect overflow -> `redirect_limit_exceeded`

## `hands/cmd/dns_enum/main.go`

| Function | Signature | Purpose |
|---|---|---|
| `main` | `func main()` | stdin/stdout bridge |
| `run` | `func run(req ToolRequest) ToolResponse` | passive + optional active orchestration |
| `applyDefaults` | `func applyDefaults(cfg DNSConfig) DNSConfig` | safe fallback defaults |
| `resolveNameServers` | `func resolveNameServers(cfg DNSConfig) []string` | combine nameserver fields |
| `includeAxfrType` | `func includeAxfrType(recordType string, allowed []string) bool` | AXFR filter override for NS/SOA |
| `normalizeDomains` | `func normalizeDomains(domains []string) []string` | lower/dedupe/sort domains |
| `contains` | `func contains(values []string, value string) bool` | case-insensitive membership |
| `now` | `func now() string` | RFC3339Nano UTC timestamp |

Collector methods:

- `addDiscovery`, `addQuery`, `addError`, `addWildcard`
- `discoveryList`, `queriesList`, `errorsList`, `wildcardsList`
- `discoveryKey`

## `hands/cmd/dns_enum/active.go`

| Function | Purpose |
|---|---|
| `resolveDomains` | worker-pooled DNS query execution with breaker |
| `handleQuery` | perform query, record telemetry, add discoveries |
| `bruteForceCandidates` | generate active candidates from wordlist |
| `filterByDepth`, `withinDepth` | depth-limiting logic |
| `normalizeRecordTypes`, `dnsType`, `dedupeStrings` | record normalization |
| `detectWildcard`, `randomLabel` | wildcard probing |
| `attemptZoneTransferRecords`, `axfrRecordFromRR` | AXFR record extraction |
| `netJoinHostPort` | normalize nameserver host:port |
| `newRateLimiter`, `(*rateLimiter).wait` | DNS query pacing |

## `hands/cmd/dns_enum/passive.go`

| Function | Signature | Purpose |
|---|---|---|
| `queryCrtSh` | `func queryCrtSh(domain string, timeout time.Duration) ([]string, error)` | passive subdomain discovery via crt.sh |

## `hands/cmd/dns_enum/resolver.go`

| Function | Purpose |
|---|---|
| `NewDNSResolver` | resolver initialization with fallback order |
| `(*DNSResolver).Query` | single DNS query against configured resolver |
| `extractAnswers` | typed RR extraction |
| `queryWithRetry` | bounded retries with exponential backoff |
| `normalizeServers` | dedupe/format nameservers |
| `loadSystemServers` | load from `/etc/resolv.conf` |

## `hands/cmd/dns_enum/wordlist.go`

| Function | Signature | Purpose |
|---|---|---|
| `loadWordlist` | `func loadWordlist(path string) ([]string, error)` | load non-empty non-comment labels |

## Concurrency and Safety Notes

- `probe`: no worker pool; simpler pacing model.
- `http_verify`: goroutine worker pool + channel jobs + mutex writer + atomic IDs.
- `dns_enum`: goroutine query workers + atomic breaker + mutex collector.

⚠️ Warning: validate concurrent summary counter behavior with `go test -race ./...` when changing `http_verify` execution accounting.
