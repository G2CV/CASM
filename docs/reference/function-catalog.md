# Complete Function Catalog

This catalog enumerates production functions/methods by file so nothing is omitted.

## Python

### `brain/cli/casm.py`

- `_env_bool`
- `_parse_bool`
- `_parse_formats`
- `_load_domains_file`
- `_dns_domains_from_scope`
- `_normalize_dns_seed`
- `_is_ip`
- `run_command`
- `http_verify_command`
- `unified_command`
- `_load_run_id`
- `dns_enum_command`
- `evidence_command`
- `migrate_command`
- `diff_command`
- `main`

### `brain/core/scope.py`

- `Scope.from_file`
- `Scope.snapshot`
- `Scope.allowed_domain_patterns`
- `ScopeGuard.__init__`
- `ScopeGuard.check_target`
- `ScopeGuard.check_domain`
- `ScopeGuard.check_rate`
- `ScopeGuard._check_ip`
- `ScopeGuard._check_domain`
- `ScopeGuard._is_excluded_domain`
- `ScopeGuard._is_ip`

### `brain/core/orchestrator.py`

- `Orchestrator.__init__`
- `Orchestrator.run`
- `Orchestrator._new_run_id`
- `_build_run_result_evidence`

### `brain/core/version.py`

- `get_casm_version`
- `_version_from_git`

### `brain/core/http_verify.py`

- `build_http_targets`
- `build_http_verify_request`

### `brain/core/dns_enum.py`

- `run_dns_enum`
- `execute_dns_enum`
- `build_dns_config`
- `normalize_domains`
- `filter_domains`
- `build_dns_events`
- `build_dns_sarif`
- `render_dns_report`
- `_event`
- `target_hash`
- `dns_fingerprint`

### `brain/core/unified.py`

- `run_unified`
- `derive_http_targets`
- `load_targets_file`
- `normalize_targets`
- `build_import_inventory`
- `build_unified_inventory`
- `merge_evidence`
- `write_evidence`
- `write_unified_sarif`
- `render_unified_report`
- `_aggregate_http_findings`
- `_probe_request`
- `_sorted_targets`
- `_target_sort_key`
- `_sorted_events`
- `_target_id`
- `_attempt_id`
- `_scheme`
- `_normalize_method`
- `_normalize_url`
- `_split_host_port`
- `_split_host_port_from_url`
- `_set_run_automation`
- `_normalize_sarif_runs`
- `_estimate_http_timeout_ms`
- `_new_run_id`
- `_dns_domains_from_scope`
- `_dns_hosts_from_discoveries`
- `_normalize_dns_seed`
- `_is_ip`

### `brain/core/inventory.py`

- `build_probe_inventory`
- `build_http_verify_inventory`
- `write_inventory`
- `_sorted`
- `_resolve_ip`
- `_is_ip`

### `brain/core/evidence_view.py`

- `parse_timestamp`
- `EvidenceStream.__init__`
- `EvidenceStream.__iter__`
- `load_evidence`
- `_contains_match`

### `brain/core/report.py`

- `render_report`
- `_derive_overall_risk`
- `_derive_recommendations`
- `_recommendation_for_finding`
- `_ordered_counts`
- `_extract_host`
- `_extract_port`

### `brain/core/sarif.py`

- `build_sarif`
- `_fingerprint`
- `_rule_id_for_finding`
- `_level_for_severity`
- `_recommendation_for_finding`

### `brain/core/diff.py`

- `diff_sarif`
- `render_diff_report`
- `_load_sarif_findings`
- `_severity_from_result`
- `_fingerprint_from_result`
- `_run_matches`
- `_sorted_findings`
- `_format_findings`

### `brain/core/migrate.py`

- `migrate_run`
- `_migrate_targets`
- `_migrate_evidence`
- `_migrate_sarif`
- `_migrate_report`
- `_ensure_sarif_version`

### `brain/core/redaction.py`

- `redact_text`
- `redact_data`

### `brain/core/url_canonical.py`

- `canonicalize_url`

### `brain/core/pdf_styles.py`

- `_hex_color`
- `get_casm_styles`

### `brain/core/pdf_report.py`

- `generate_pdf_report`
- `_build_doc`
- `_after_flowable`
- `_first_page`
- `_later_pages`
- `_draw_header`
- `_draw_footer`
- `calculate_summary_stats`
- `create_cover_page`
- `create_executive_summary`
- `create_table_of_contents`
- `create_scope_section`
- `create_dns_section`
- `create_findings_section`
- `create_port_scan_section`
- `create_appendix`
- `create_severity_table`
- `create_dns_tables`
- `create_port_table`
- `_finding_block`
- `_group_findings`
- `_load_evidence`
- `_load_targets`
- `_load_sarif_findings`
- `_time_span`
- `_parse_timestamp`
- `_format_datetime`
- `_default_recommendations`
- `_validate_branding`
- `_diff_settings`
- `create_diff_section`
- `_find_baseline_info`
- `_parse_run_timestamp`
- `_load_sarif_records`
- `_sarif_severity_counts`
- `_severity_from_result`
- `_normalize_severity`
- `_fingerprint_from_result`
- `_diff_summary_table`
- `_format_change`
- `_filter_diff`
- `_render_new_critical`
- `_render_new_high`
- `_render_resolved`
- `_render_dns_changes`
- `_collect_trend_data`
- `_render_trend`
- `_trend_summary`
- `_diff_dns`
- `_dns_records`
- `_count_open_ports`
- `_count_dns_subdomains`

### Adapters, ports, scripts

- `ToolGatewayAdapter.__init__`, `ToolGatewayAdapter.run`
- `HttpVerifyGateway.run`
- `DnsEnumGateway.run`
- `FileSystemEvidenceStore.write`
- `NoopPublisher.publish`
- `ToolGateway.run` (protocol)
- `EvidenceStore.write` (protocol)
- `Publisher.publish` (protocol)

## Go

### `hands/cmd/probe/main.go`

- `main`
- `writeError`
- `writeResponse`

### `hands/cmd/http_verify/main.go`

- `newEvidenceWriter`
- `(*evidenceWriter).close`
- `(*evidenceWriter).write`
- `(*evidenceWriter).nextID`
- `main`
- `defaults`
- `run`
- `buildClient`
- `newRateLimiter`
- `(*rateLimiter).wait`
- `handleTarget`
- `executeRequest`
- `doOnce`
- `buildResult`
- `allowlistHeaders`
- `headerObservations`
- `tlsDetails`
- `tlsVersion`
- `tlsExpiresSoon`
- `checkScope`
- `portFromURL`
- `contains`
- `containsInt`
- `isIP`
- `ipInScope`
- `eventFrom`
- `writeSarif`
- `buildFindings`
- `sarifForObservation`
- `sarifRules`
- `ruleDescription`
- `ruleSeverity`
- `sarifLevelForSeverity`
- `allRuleIDs`
- `isTextLikeMediaType`
- `hasCharset`
- `buildTLSConfig`
- `tlsErrorReason`
- `canonicalizeAttemptURL`
- `cspHasFrameAncestors`
- `sarifResults`
- `buildNotifications`
- `canonicalAttemptURL`
- `validateSarifRules`
- `canonicalEndpoint`
- `canonicalizeRedirectChain`
- `canonicalizeURL`
- `firstOrEmpty`
- `firstString`
- `firstRedirectChain`
- `findingFingerprint`
- `fingerprintsForResult`
- `observationToRule`
- `finalScheme`

### `hands/cmd/dns_enum/main.go`

- `main`
- `run`
- `applyDefaults`
- `resolveNameServers`
- `includeAxfrType`
- `normalizeDomains`
- `contains`
- `now`
- `(*resultCollector).addDiscovery`
- `(*resultCollector).addQuery`
- `(*resultCollector).addError`
- `(*resultCollector).addWildcard`
- `(*resultCollector).discoveryList`
- `(*resultCollector).queriesList`
- `(*resultCollector).errorsList`
- `(*resultCollector).wildcardsList`
- `discoveryKey`

### `hands/cmd/dns_enum/active.go`

- `resolveDomains`
- `handleQuery`
- `bruteForceCandidates`
- `filterByDepth`
- `withinDepth`
- `normalizeRecordTypes`
- `dnsType`
- `dedupeStrings`
- `detectWildcard`
- `randomLabel`
- `attemptZoneTransferRecords`
- `axfrRecordFromRR`
- `netJoinHostPort`
- `newRateLimiter`
- `(*rateLimiter).wait`

### `hands/cmd/dns_enum/passive.go`

- `queryCrtSh`

### `hands/cmd/dns_enum/resolver.go`

- `NewDNSResolver`
- `(*DNSResolver).Query`
- `extractAnswers`
- `queryWithRetry`
- `normalizeServers`
- `loadSystemServers`

### `hands/cmd/dns_enum/wordlist.go`

- `loadWordlist`
