package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const toolName = "dns_enum"

var toolVersion = "dev"

type ToolRequest struct {
	EngagementID string    `json:"engagement_id"`
	RunID        string    `json:"run_id"`
	DryRun       bool      `json:"dry_run"`
	Config       DNSConfig `json:"config"`
}

type DNSConfig struct {
	Domains                []string     `json:"domains"`
	WordlistPath           string       `json:"wordlist_path"`
	PassiveOnly            bool         `json:"passive_only"`
	PassiveSources         []string     `json:"passive_sources"`
	NameServer             string       `json:"nameserver"`
	NameServers            []string     `json:"nameservers"`
	RateLimit              int          `json:"rate_limit"`
	TimeoutMS              int          `json:"timeout"`
	MaxDepth               int          `json:"max_depth"`
	MaxConsecutiveFailures int          `json:"max_consecutive_failures"`
	RecordTypes            []string     `json:"record_types"`
	CheckZoneTransfer      bool         `json:"check_zone_transfer"`
	DetectWildcard         bool         `json:"detect_wildcard"`
	ActiveDiscovery        ActiveConfig `json:"active_discovery"`
}

type ActiveConfig struct {
	Enabled     bool   `json:"enabled"`
	Wordlist    string `json:"wordlist"`
	RateLimit   int    `json:"rate_limit"`
	TimeoutMS   int    `json:"timeout"`
	MaxDepth    int    `json:"max_depth"`
	Concurrency int    `json:"concurrency"`
}

type ToolResponse struct {
	OK            bool            `json:"ok"`
	BlockedReason *string         `json:"blocked_reason"`
	ToolName      string          `json:"tool_name"`
	ToolVersion   string          `json:"tool_version"`
	Discoveries   []Discovery     `json:"discoveries"`
	Queries       []QueryEvent    `json:"queries"`
	Errors        []ErrorEvent    `json:"errors"`
	Wildcards     []WildcardEvent `json:"wildcards"`
	Metrics       map[string]any  `json:"metrics"`
}

type Discovery struct {
	Domain          string   `json:"domain"`
	Subdomain       string   `json:"subdomain"`
	RecordType      string   `json:"record_type"`
	Values          []string `json:"values"`
	Source          string   `json:"source"`
	DiscoveryMethod string   `json:"discovery_method"`
	FirstSeen       string   `json:"first_seen"`
	Timestamp       string   `json:"timestamp"`
}

type QueryEvent struct {
	Domain          string `json:"domain"`
	Subdomain       string `json:"subdomain"`
	RecordType      string `json:"record_type"`
	Source          string `json:"source"`
	DiscoveryMethod string `json:"discovery_method"`
	Status          string `json:"status"`
	Error           string `json:"error"`
	DurationMS      int64  `json:"duration_ms"`
	Timestamp       string `json:"timestamp"`
}

type ErrorEvent struct {
	Domain          string `json:"domain"`
	Subdomain       string `json:"subdomain"`
	RecordType      string `json:"record_type"`
	Source          string `json:"source"`
	DiscoveryMethod string `json:"discovery_method"`
	Error           string `json:"error"`
	Timestamp       string `json:"timestamp"`
}

type WildcardEvent struct {
	Domain     string   `json:"domain"`
	RecordType string   `json:"record_type"`
	Values     []string `json:"values"`
	Source     string   `json:"source"`
	Timestamp  string   `json:"timestamp"`
}

type resultCollector struct {
	mu          sync.Mutex
	discoveries map[string]Discovery
	queries     []QueryEvent
	errors      []ErrorEvent
	wildcards   []WildcardEvent
}

func main() {
	// main reads JSON input and emits a ToolResponse for orchestration.
	reader := bufio.NewReader(os.Stdin)
	var req ToolRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		reason := "invalid_request"
		_ = json.NewEncoder(os.Stdout).Encode(ToolResponse{OK: false, BlockedReason: &reason, ToolName: toolName, ToolVersion: toolVersion})
		return
	}

	response := run(req)
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func run(req ToolRequest) ToolResponse {
	// run executes passive + optional active enumeration and aggregates results.
	if req.DryRun {
		reason := "dry_run"
		return ToolResponse{OK: false, BlockedReason: &reason, ToolName: toolName, ToolVersion: toolVersion}
	}

	cfg := applyDefaults(req.Config)
	domains := normalizeDomains(cfg.Domains)
	if len(domains) == 0 {
		reason := "no_domains"
		return ToolResponse{OK: false, BlockedReason: &reason, ToolName: toolName, ToolVersion: toolVersion}
	}

	collector := &resultCollector{discoveries: map[string]Discovery{}}
	resolver := NewDNSResolver(time.Duration(cfg.TimeoutMS)*time.Millisecond, resolveNameServers(cfg))

	if contains(cfg.PassiveSources, "crt.sh") {
		for _, domain := range domains {
			subdomains, err := queryCrtSh(domain, time.Duration(cfg.TimeoutMS)*time.Millisecond)
			if err != nil {
				collector.addError(ErrorEvent{
					Domain:          domain,
					Subdomain:       "",
					RecordType:      "",
					Source:          "crt.sh",
					DiscoveryMethod: "passive",
					Error:           err.Error(),
					Timestamp:       now(),
				})
				continue
			}
			discovered := filterByDepth(domain, subdomains, cfg.MaxDepth)
			resolveDomains(domain, discovered, cfg, "crt.sh", "passive", resolver, collector)
		}
	}

	if !cfg.PassiveOnly && cfg.ActiveDiscovery.Enabled {
		activeCfg := cfg.ActiveDiscovery
		if activeCfg.TimeoutMS <= 0 {
			activeCfg.TimeoutMS = cfg.TimeoutMS
		}
		if activeCfg.RateLimit <= 0 {
			activeCfg.RateLimit = cfg.RateLimit
		}
		if activeCfg.MaxDepth <= 0 {
			activeCfg.MaxDepth = cfg.MaxDepth
		}
		if activeCfg.Concurrency <= 0 {
			activeCfg.Concurrency = 4
		}
		activeRun := cfg
		activeRun.TimeoutMS = activeCfg.TimeoutMS
		activeRun.RateLimit = activeCfg.RateLimit
		activeRun.MaxDepth = activeCfg.MaxDepth
		activeRun.ActiveDiscovery = activeCfg

		wordlistPath := activeCfg.Wordlist
		if wordlistPath == "" {
			wordlistPath = cfg.WordlistPath
		}
		words, err := loadWordlist(wordlistPath)
		if err != nil {
			collector.addError(ErrorEvent{
				Domain:          "",
				Subdomain:       "",
				RecordType:      "",
				Source:          "wordlist",
				DiscoveryMethod: "active",
				Error:           err.Error(),
				Timestamp:       now(),
			})
		} else {
			for _, domain := range domains {
				candidates := bruteForceCandidates(domain, words, activeCfg.MaxDepth)
				resolveDomains(domain, candidates, activeRun, "wordlist", "active", resolver, collector)
			}
		}

		if cfg.DetectWildcard {
			for _, domain := range domains {
				wildcard := detectWildcard(domain, activeRun, resolver, collector)
				if wildcard != nil {
					collector.addWildcard(*wildcard)
				}
			}
		}

		if cfg.CheckZoneTransfer {
			for _, domain := range domains {
				records, err := attemptZoneTransferRecords(domain, resolver, time.Duration(activeCfg.TimeoutMS)*time.Millisecond)
				if err != nil {
					collector.addError(ErrorEvent{
						Domain:          domain,
						Subdomain:       "",
						RecordType:      "AXFR",
						Source:          "axfr",
						DiscoveryMethod: "active",
						Error:           err.Error(),
						Timestamp:       now(),
					})
					continue
				}
				allowedTypes := normalizeRecordTypes(cfg.RecordTypes)
				for _, record := range records {
					if !withinDepth(domain, record.name, activeCfg.MaxDepth) {
						continue
					}
					if !includeAxfrType(record.rtype, allowedTypes) {
						continue
					}
					ts := now()
					collector.addDiscovery(Discovery{
						Domain:          domain,
						Subdomain:       record.name,
						RecordType:      record.rtype,
						Values:          dedupeStrings(record.values),
						Source:          "axfr",
						DiscoveryMethod: "active",
						FirstSeen:       ts,
						Timestamp:       ts,
					})
				}
			}
		}
	}

	discoveries := collector.discoveryList()
	return ToolResponse{
		OK:          true,
		ToolName:    toolName,
		ToolVersion: toolVersion,
		Discoveries: discoveries,
		Queries:     collector.queriesList(),
		Errors:      collector.errorsList(),
		Wildcards:   collector.wildcardsList(),
		Metrics: map[string]any{
			"discoveries": len(discoveries),
			"queries":     len(collector.queriesList()),
			"errors":      len(collector.errorsList()),
		},
	}
}

func applyDefaults(cfg DNSConfig) DNSConfig {
	// applyDefaults ensures minimal operational settings for standalone runs.
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = 5000
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 10
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 1
	}
	if cfg.MaxConsecutiveFailures <= 0 {
		cfg.MaxConsecutiveFailures = 20
	}
	if len(cfg.RecordTypes) == 0 {
		cfg.RecordTypes = []string{"A", "AAAA", "CNAME"}
	}
	if cfg.PassiveSources == nil {
		cfg.PassiveSources = []string{"crt.sh"}
	}
	return cfg
}

func resolveNameServers(cfg DNSConfig) []string {
	// resolveNameServers merges single and list-based resolver config.
	servers := []string{}
	if cfg.NameServer != "" {
		servers = append(servers, cfg.NameServer)
	}
	servers = append(servers, cfg.NameServers...)
	return servers
}

func includeAxfrType(recordType string, allowed []string) bool {
	// includeAxfrType keeps AXFR output useful even when filtering record types.
	upper := strings.ToUpper(recordType)
	if upper == "NS" || upper == "SOA" {
		return true
	}
	for _, item := range allowed {
		if strings.ToUpper(item) == upper {
			return true
		}
	}
	return false
}

func normalizeDomains(domains []string) []string {
	// normalizeDomains lowercases and dedupes domains for consistent queries.
	seen := map[string]bool{}
	var out []string
	for _, raw := range domains {
		value := strings.ToLower(strings.TrimSpace(raw))
		value = strings.TrimSuffix(value, ".")
		if value == "" {
			continue
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func (rc *resultCollector) addDiscovery(item Discovery) {
	// addDiscovery dedupes discoveries to reduce noisy output.
	rc.mu.Lock()
	defer rc.mu.Unlock()
	key := discoveryKey(item)
	rc.discoveries[key] = item
}

func (rc *resultCollector) addQuery(item QueryEvent) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.queries = append(rc.queries, item)
}

func (rc *resultCollector) addError(item ErrorEvent) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.errors = append(rc.errors, item)
}

func (rc *resultCollector) addWildcard(item WildcardEvent) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.wildcards = append(rc.wildcards, item)
}

func (rc *resultCollector) discoveryList() []Discovery {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]Discovery, 0, len(rc.discoveries))
	for _, item := range rc.discoveries {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subdomain == out[j].Subdomain {
			return out[i].RecordType < out[j].RecordType
		}
		return out[i].Subdomain < out[j].Subdomain
	})
	return out
}

func (rc *resultCollector) queriesList() []QueryEvent {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]QueryEvent, len(rc.queries))
	copy(out, rc.queries)
	return out
}

func (rc *resultCollector) errorsList() []ErrorEvent {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]ErrorEvent, len(rc.errors))
	copy(out, rc.errors)
	return out
}

func (rc *resultCollector) wildcardsList() []WildcardEvent {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]WildcardEvent, len(rc.wildcards))
	copy(out, rc.wildcards)
	return out
}

func discoveryKey(item Discovery) string {
	// discoveryKey collapses equivalent records for stable reporting.
	values := append([]string{}, item.Values...)
	sort.Strings(values)
	return strings.ToLower(item.Subdomain) + "|" + strings.ToUpper(item.RecordType) + "|" + strings.Join(values, ",")
}
