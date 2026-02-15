package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const toolName = "http_verify"

var toolVersion = "dev"

const schemaVersion = "1.0.0"

type ToolRequest struct {
	EngagementID string      `json:"engagement_id"`
	RunID        string      `json:"run_id"`
	DryRun       bool        `json:"dry_run"`
	Debug        bool        `json:"debug"`
	Profile      string      `json:"profile"`
	TLS          TLSOptions  `json:"tls"`
	HTTPSPorts   []int       `json:"https_ports"`
	Scope        Scope       `json:"scope"`
	Targets      []Target    `json:"targets"`
	Limits       Limits      `json:"limits"`
	Evidence     EvidenceOut `json:"evidence"`
	Sarif        SarifOut    `json:"sarif"`
}

type TLSOptions struct {
	CABundlePath       string `json:"ca_bundle_path"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	ServerName         string `json:"server_name"`
}

type Scope struct {
	AllowedDomains   []string `json:"allowed_domains"`
	AllowedIPs       []string `json:"allowed_ips"`
	AllowedPorts     []int    `json:"allowed_ports"`
	AllowedProtocols []string `json:"allowed_protocols"`
}

type Target struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

type Limits struct {
	MaxConcurrency int `json:"max_concurrency"`
	RPS            int `json:"rps"`
	TimeoutMS      int `json:"timeout_ms"`
	MaxRedirects   int `json:"max_redirects"`
	MaxBodyBytes   int `json:"max_body_bytes"`
	TLSExpiryDays  int `json:"tls_expiry_days"`
}

type EvidenceOut struct {
	JSONLPath string `json:"jsonl_path"`
}

type SarifOut struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type ToolResponse struct {
	ToolName    string        `json:"tool_name"`
	ToolVersion string        `json:"tool_version"`
	RunID       string        `json:"run_id"`
	Summary     Summary       `json:"summary"`
	Results     []ResultEntry `json:"results"`
}

type Summary struct {
	Attempted int `json:"attempted"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Blocked   int `json:"blocked"`
}

type ResultEntry struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	FinalURL        string            `json:"final_url"`
	RedirectChain   []string          `json:"redirect_chain"`
	Headers         map[string]string `json:"headers"`
	ObservedHeaders map[string]string `json:"observed_headers"`
	TLS             *TLSInfo          `json:"tls"`
	TLSMode         string            `json:"tls_mode"`
	Observations    []Observation     `json:"observations"`
	DurationMS      int64             `json:"duration_ms"`
	Error           string            `json:"error"`
}

type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	CertSubject string `json:"cert_subject"`
	CertIssuer  string `json:"cert_issuer"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

type Observation struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type EvidenceEvent struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Timestamp     string         `json:"timestamp"`
	SchemaVersion string         `json:"schema_version"`
	EngagementID  string         `json:"engagement_id"`
	RunID         string         `json:"run_id"`
	ToolName      string         `json:"tool_name"`
	ToolVersion   string         `json:"tool_version"`
	Data          map[string]any `json:"data"`
}

type evidenceWriter struct {
	mu     sync.Mutex
	writer *bufio.Writer
	file   *os.File
	count  int64
}

func newEvidenceWriter(path string) (*evidenceWriter, error) {
	// newEvidenceWriter ensures the evidence path exists and returns a buffered writer
	// to reduce overhead from high-volume event emission.
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &evidenceWriter{writer: bufio.NewWriter(file), file: file}, nil
}

func (ew *evidenceWriter) close() error {
	// close flushes buffered evidence so partial runs still preserve output.
	ew.mu.Lock()
	defer ew.mu.Unlock()
	if err := ew.writer.Flush(); err != nil {
		_ = ew.file.Close()
		return err
	}
	return ew.file.Close()
}

func (ew *evidenceWriter) write(event EvidenceEvent) error {
	// write serializes evidence as JSONL to keep streaming consumers simple.
	ew.mu.Lock()
	defer ew.mu.Unlock()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := ew.writer.Write(data); err != nil {
		return err
	}
	if err := ew.writer.WriteByte('\n'); err != nil {
		return err
	}
	return nil
}

func (ew *evidenceWriter) nextID(runID string) string {
	// nextID produces stable, monotonically increasing IDs for evidence ordering.
	value := atomic.AddInt64(&ew.count, 1)
	return fmt.Sprintf("%s-%06d", runID, value)
}

func main() {
	// main bridges stdin/stdout JSON so the tool can be driven by orchestration.
	reader := bufio.NewReader(os.Stdin)
	var req ToolRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(ToolResponse{ToolName: toolName, ToolVersion: toolVersion, RunID: ""})
		return
	}

	defaults(&req)
	response := run(req)
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func defaults(req *ToolRequest) {
	// defaults keep the tool usable when callers omit optional limits.
	if req.Limits.MaxConcurrency <= 0 {
		req.Limits.MaxConcurrency = 4
	}
	if req.Limits.RPS <= 0 {
		req.Limits.RPS = 5
	}
	if req.Limits.TimeoutMS <= 0 {
		req.Limits.TimeoutMS = 8000
	}
	if req.Limits.MaxRedirects <= 0 {
		req.Limits.MaxRedirects = 5
	}
	if req.Limits.MaxBodyBytes <= 0 {
		req.Limits.MaxBodyBytes = 32768
	}
	if req.Limits.TLSExpiryDays <= 0 {
		req.Limits.TLSExpiryDays = 30
	}
	if req.Profile == "" {
		req.Profile = "baseline"
	}
	if len(req.HTTPSPorts) == 0 {
		req.HTTPSPorts = []int{443}
	}
}

func run(req ToolRequest) ToolResponse {
	// run executes HTTP verification, writing evidence and optional SARIF.
	if req.Evidence.JSONLPath == "" {
		return ToolResponse{ToolName: toolName, ToolVersion: toolVersion, RunID: req.RunID}
	}
	writer, err := newEvidenceWriter(req.Evidence.JSONLPath)
	if err != nil {
		return ToolResponse{ToolName: toolName, ToolVersion: toolVersion, RunID: req.RunID}
	}
	defer writer.close()

	tlsConfig, tlsMode, err := buildTLSConfig(req.TLS)
	if err != nil {
		return ToolResponse{ToolName: toolName, ToolVersion: toolVersion, RunID: req.RunID}
	}
	client := buildClient(req.Limits.TimeoutMS, tlsConfig)
	results := make([]ResultEntry, len(req.Targets))
	var summary Summary

	jobs := make(chan int)
	var wg sync.WaitGroup
	limiter := newRateLimiter(req.Limits.RPS)

	for i := 0; i < req.Limits.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				target := req.Targets[idx]
				result := handleTarget(req, client, limiter, writer, target, tlsMode)
				results[idx] = result
				summary.Attempted++
				switch {
				case result.Error == "blocked":
					summary.Blocked++
				case result.Error == "":
					summary.Succeeded++
				default:
					summary.Failed++
				}
			}
		}()
	}

	for idx := range req.Targets {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()

	_ = writer.write(EvidenceEvent{
		ID:            writer.nextID(req.RunID),
		Type:          "run_summary",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		SchemaVersion: schemaVersion,
		EngagementID:  req.EngagementID,
		RunID:         req.RunID,
		ToolName:      toolName,
		ToolVersion:   toolVersion,
		Data: map[string]any{
			"attempted": summary.Attempted,
			"succeeded": summary.Succeeded,
			"failed":    summary.Failed,
			"blocked":   summary.Blocked,
		},
	})

	if req.Sarif.Enabled {
		_ = writeSarif(req, results)
	}

	return ToolResponse{
		ToolName:    toolName,
		ToolVersion: toolVersion,
		RunID:       req.RunID,
		Summary:     summary,
		Results:     results,
	}
}

func buildClient(timeoutMS int, tlsConfig *tls.Config) *http.Client {
	// buildClient applies tight timeouts to avoid hanging on slow endpoints.
	dialer := &net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   time.Duration(timeoutMS) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(timeoutMS) * time.Millisecond,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type rateLimiter struct {
	ch <-chan time.Time
}

func newRateLimiter(rps int) *rateLimiter {
	// newRateLimiter spaces requests to respect per-run rate policies.
	if rps <= 0 {
		return &rateLimiter{ch: nil}
	}
	interval := time.Second / time.Duration(rps)
	return &rateLimiter{ch: time.Tick(interval)}
}

func (rl *rateLimiter) wait() {
	// wait blocks until the next rate slot is available.
	if rl.ch == nil {
		return
	}
	<-rl.ch
}

func handleTarget(req ToolRequest, client *http.Client, limiter *rateLimiter, writer *evidenceWriter, target Target, tlsMode string) ResultEntry {
	// handleTarget enforces scope + dry-run rules and records evidence for each attempt.
	start := time.Now()
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = "HEAD"
	}
	if method != "HEAD" && method != "GET" {
		method = "HEAD"
	}

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return ResultEntry{
			URL:             target.URL,
			Method:          method,
			Error:           err.Error(),
			TLSMode:         tlsMode,
			Headers:         map[string]string{},
			ObservedHeaders: map[string]string{},
		}
	}
	parsed = canonicalizeAttemptURL(parsed, req.HTTPSPorts)
	attemptedURL := parsed.String()

	blockedReason := checkScope(req.Scope, parsed)
	if blockedReason != "" {
		_ = writer.write(eventFrom(req, writer, "http_blocked", map[string]any{
			"url":           attemptedURL,
			"method":        method,
			"reason":        blockedReason,
			"status":        "blocked",
			"canonical_url": canonicalizeURL(attemptedURL),
			"tls_mode":      tlsMode,
		}))
		return ResultEntry{
			URL:             target.URL,
			Method:          method,
			Error:           "blocked",
			TLSMode:         tlsMode,
			Headers:         map[string]string{},
			ObservedHeaders: map[string]string{},
		}
	}

	if req.DryRun {
		_ = writer.write(eventFrom(req, writer, "http_blocked", map[string]any{
			"url":           attemptedURL,
			"method":        method,
			"reason":        "dry_run",
			"status":        "blocked",
			"canonical_url": canonicalizeURL(attemptedURL),
			"tls_mode":      tlsMode,
		}))
		return ResultEntry{
			URL:             target.URL,
			Method:          method,
			Error:           "blocked",
			TLSMode:         tlsMode,
			Headers:         map[string]string{},
			ObservedHeaders: map[string]string{},
		}
	}

	limiter.wait()
	_ = writer.write(eventFrom(req, writer, "http_attempt", map[string]any{
		"url":           attemptedURL,
		"method":        method,
		"scope":         "allowed",
		"status":        "attempt",
		"canonical_url": canonicalizeURL(attemptedURL),
	}))

	result, err := executeRequest(req, client, method, parsed)
	if err != nil {
		errType := "error"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
			errType = "timeout"
		}
		errMsg := tlsErrorReason(err)
		if errMsg == "" {
			errMsg = err.Error()
		}
		_ = writer.write(eventFrom(req, writer, "http_error", map[string]any{
			"url":           attemptedURL,
			"method":        method,
			"error":         errMsg,
			"status":        errType,
			"duration":      time.Since(start).Milliseconds(),
			"canonical_url": canonicalizeURL(attemptedURL),
			"tls_mode":      tlsMode,
		}))
		return ResultEntry{
			URL:             attemptedURL,
			Method:          method,
			Error:           errMsg,
			DurationMS:      time.Since(start).Milliseconds(),
			TLSMode:         tlsMode,
			Headers:         map[string]string{},
			ObservedHeaders: map[string]string{},
		}
	}

	result.DurationMS = time.Since(start).Milliseconds()
	result.TLSMode = tlsMode
	fingerprints := fingerprintsForResult(result, req.Profile)
	_ = writer.write(eventFrom(req, writer, "http_response", map[string]any{
		"url":                      attemptedURL,
		"method":                   method,
		"status_code":              result.StatusCode,
		"final_url":                result.FinalURL,
		"redirect_chain":           result.RedirectChain,
		"canonical_url":            canonicalizeURL(result.FinalURL),
		"canonical_redirect_chain": canonicalizeRedirectChain(result.RedirectChain),
		"finding_fingerprints":     fingerprints,
		"finding_fingerprint":      firstString(fingerprints),
		"headers":                  result.Headers,
		"tls":                      result.TLS,
		"duration_ms":              result.DurationMS,
		"status":                   "success",
		"tls_mode":                 tlsMode,
	}))
	if req.Debug {
		if value, ok := result.Headers["content-type"]; ok {
			fmt.Fprintf(os.Stderr, "observed content-type=\"%s\" url=\"%s\"\n", value, result.FinalURL)
		}
		_ = writer.write(eventFrom(req, writer, "http_debug_headers", map[string]any{
			"url":     result.FinalURL,
			"headers": result.Headers,
		}))
	}

	return result
}

func executeRequest(req ToolRequest, client *http.Client, method string, parsed *url.URL) (ResultEntry, error) {
	// executeRequest follows redirects up to MaxRedirects and captures observations.
	current := parsed
	redirects := []string{}
	maxRedirects := req.Limits.MaxRedirects
	for i := 0; i <= maxRedirects; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Limits.TimeoutMS)*time.Millisecond)
		resp, err := doOnce(ctx, client, method, current, req.Limits.MaxBodyBytes)
		cancel()
		if err != nil {
			return ResultEntry{URL: parsed.String(), Method: method, Error: err.Error()}, err
		}
		if (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) && method == "HEAD" {
			_ = resp.Body.Close()
			method = "GET"
			continue
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				_ = resp.Body.Close()
				return buildResult(resp, parsed, current, redirects), nil
			}
			redirects = append(redirects, location)
			nextURL, err := current.Parse(location)
			if err != nil {
				_ = resp.Body.Close()
				return ResultEntry{URL: parsed.String(), Method: method, Error: err.Error()}, err
			}
			_ = resp.Body.Close()
			current = nextURL
			continue
		}
		defer resp.Body.Close()
		result := buildResult(resp, parsed, current, redirects)
		result.Observations = append(
			result.Observations,
			headerObservations(result.Headers, current.Scheme, result.TLS != nil, req.Profile)...,
		)
		if resp.TLS != nil {
			expiresSoon := tlsExpiresSoon(resp.TLS, req.Limits.TLSExpiryDays)
			if expiresSoon {
				result.Observations = append(result.Observations, Observation{Type: "tls_cert_expires_soon", Key: ""})
			}
		}
		if parsed.Scheme == "https" && current.Scheme == "http" {
			result.Observations = append(result.Observations, Observation{Type: "https_downgrade_redirect", Key: ""})
		}
		if parsed.Scheme == "http" && current.Scheme == "http" {
			result.Observations = append(result.Observations, Observation{Type: "http_not_https", Key: ""})
		}
		return result, nil
	}

	return ResultEntry{URL: parsed.String(), Method: method, Error: "redirect_limit_exceeded"}, errors.New("redirect_limit_exceeded")
}

func doOnce(ctx context.Context, client *http.Client, method string, target *url.URL, maxBody int) (*http.Response, error) {
	// doOnce performs a single HTTP request and caps body reads for safety.
	req, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if method == "GET" {
		_, _ = io.CopyN(io.Discard, resp.Body, int64(maxBody))
	}
	return resp, nil
}

func buildResult(resp *http.Response, original *url.URL, current *url.URL, redirects []string) ResultEntry {
	// buildResult normalizes response fields so downstream reporting is stable.
	headers := allowlistHeaders(resp.Header)
	var tlsInfo *TLSInfo
	if resp.TLS != nil {
		tlsInfo = tlsDetails(resp.TLS)
	}
	return ResultEntry{
		URL:             original.String(),
		Method:          resp.Request.Method,
		StatusCode:      resp.StatusCode,
		FinalURL:        current.String(),
		RedirectChain:   redirects,
		Headers:         headers,
		ObservedHeaders: headers,
		TLS:             tlsInfo,
		Observations:    []Observation{},
	}
}

func allowlistHeaders(headers http.Header) map[string]string {
	// allowlistHeaders limits stored headers to security-relevant fields.
	allow := map[string]struct{}{
		"strict-transport-security":    {},
		"content-security-policy":      {},
		"content-type":                 {},
		"cross-origin-opener-policy":   {},
		"cross-origin-embedder-policy": {},
		"cross-origin-resource-policy": {},
		"x-frame-options":              {},
		"x-content-type-options":       {},
		"referrer-policy":              {},
	}
	result := map[string]string{}
	for key, values := range headers {
		lower := strings.ToLower(key)
		if _, ok := allow[lower]; ok {
			result[lower] = strings.Join(values, ", ")
		}
	}
	return result
}

func headerObservations(headers map[string]string, scheme string, tlsPresent bool, profile string) []Observation {
	// headerObservations maps header presence into structured observations.
	required := []string{
		"content-security-policy",
		"x-frame-options",
		"x-content-type-options",
		"referrer-policy",
	}
	if scheme == "https" && tlsPresent {
		required = append([]string{"strict-transport-security"}, required...)
	}
	var observations []Observation
	for _, key := range required {
		if _, ok := headers[key]; !ok {
			observations = append(observations, Observation{Type: "header_missing", Key: key})
		}
	}
	contentType, hasContentType := headers["content-type"]
	if !hasContentType {
		observations = append(observations, Observation{Type: "missing_content_type", Key: "content-type"})
	} else if isTextLikeMediaType(contentType) && !hasCharset(contentType) {
		observations = append(observations, Observation{Type: "missing_charset", Key: "content-type"})
	}

	cspValue, hasCsp := headers["content-security-policy"]
	_, hasXfo := headers["x-frame-options"]
	if hasCsp {
		if !cspHasFrameAncestors(cspValue) {
			observations = append(observations, Observation{Type: "csp_missing_frame_ancestors", Key: "content-security-policy"})
			if !hasXfo {
				observations = append(observations, Observation{Type: "missing_anti_embedding", Key: "anti-embedding"})
			}
		}
	} else if !hasXfo {
		observations = append(observations, Observation{Type: "missing_anti_embedding", Key: "anti-embedding"})
	}

	if profile == "web_hardening" {
		if strings.HasPrefix(strings.ToLower(contentType), "text/html") {
			if _, ok := headers["cross-origin-opener-policy"]; !ok {
				observations = append(observations, Observation{Type: "missing_coop", Key: "cross-origin-opener-policy"})
			}
			if _, ok := headers["cross-origin-embedder-policy"]; !ok {
				observations = append(observations, Observation{Type: "missing_coep", Key: "cross-origin-embedder-policy"})
			}
			if _, ok := headers["cross-origin-resource-policy"]; !ok {
				observations = append(observations, Observation{Type: "missing_corp", Key: "cross-origin-resource-policy"})
			}
		}
	}
	return observations
}

func tlsDetails(state *tls.ConnectionState) *TLSInfo {
	// tlsDetails extracts a minimal TLS summary for reporting.
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]
	return &TLSInfo{
		Version:     tlsVersion(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		CertSubject: cert.Subject.String(),
		CertIssuer:  cert.Issuer.String(),
		NotBefore:   cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
	}
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return "unknown"
	}
}

func tlsExpiresSoon(state *tls.ConnectionState, days int) bool {
	// tlsExpiresSoon flags certificates expiring within the given window.
	if len(state.PeerCertificates) == 0 {
		return false
	}
	threshold := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	return state.PeerCertificates[0].NotAfter.Before(threshold)
}

func checkScope(scope Scope, target *url.URL) string {
	// checkScope returns a blocking reason when the target violates scope policy.
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" {
		return "protocol_not_allowed"
	}
	if !contains(scope.AllowedProtocols, scheme) {
		return "protocol_not_allowed"
	}
	port := portFromURL(target)
	if !containsInt(scope.AllowedPorts, port) {
		return "port_not_allowed"
	}
	host := target.Hostname()
	if isIP(host) {
		if !ipInScope(host, scope.AllowedIPs) {
			return "ip_out_of_scope"
		}
		return ""
	}
	for _, pattern := range scope.AllowedDomains {
		if ok, _ := path.Match(pattern, host); ok {
			return ""
		}
	}
	return "domain_out_of_scope"
}

func portFromURL(u *url.URL) int {
	if u.Port() != "" {
		if p, err := net.LookupPort("tcp", u.Port()); err == nil {
			return p
		}
	}
	if strings.ToLower(u.Scheme) == "https" {
		return 443
	}
	return 80
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func containsInt(values []int, value int) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func isIP(host string) bool {
	return net.ParseIP(host) != nil
}

func ipInScope(host string, allowed []string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range allowed {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func eventFrom(req ToolRequest, writer *evidenceWriter, eventType string, data map[string]any) EvidenceEvent {
	// eventFrom stamps shared metadata so evidence lines are self-contained.
	return EvidenceEvent{
		ID:            writer.nextID(req.RunID),
		Type:          eventType,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		SchemaVersion: schemaVersion,
		EngagementID:  req.EngagementID,
		RunID:         req.RunID,
		ToolName:      toolName,
		ToolVersion:   toolVersion,
		Data:          data,
	}
}

func writeSarif(req ToolRequest, results []ResultEntry) error {
	// writeSarif emits a SARIF report for CI and external tooling.
	findings := buildFindings(results)
	notifications := buildNotifications(results)
	sarif := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"properties": map[string]any{
			"schema_version": schemaVersion,
		},
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    "CASM",
						"version": toolVersion,
						"rules":   sarifRules(),
					},
				},
				"properties": map[string]any{
					"schema_version": schemaVersion,
				},
				"results": sarifResults(findings, req),
				"invocations": []any{
					map[string]any{
						"executionSuccessful":        true,
						"toolExecutionNotifications": notifications,
					},
				},
			},
		},
	}
	if err := validateSarifRules(sarif); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(req.Sarif.Path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(req.Sarif.Path, data, 0644)
}

type sarifFinding struct {
	RuleID         string
	Level          string
	Message        string
	URL            string
	Method         string
	OriginalURLs   []string
	RedirectChains [][]string
}

func buildFindings(results []ResultEntry) []sarifFinding {
	// buildFindings deduplicates findings by rule and canonical endpoint.
	var findings []sarifFinding
	seen := map[string]*sarifFinding{}
	for _, result := range results {
		for _, obs := range result.Observations {
			ruleID, level, message, ok := observationToRule(obs, result)
			if !ok {
				continue
			}
			endpoint := canonicalEndpoint(result)
			key := fmt.Sprintf("%s|%s", ruleID, endpoint)
			if existing, ok := seen[key]; ok {
				existing.OriginalURLs = append(existing.OriginalURLs, result.URL)
				existing.RedirectChains = append(existing.RedirectChains, result.RedirectChain)
				continue
			}
			entry := sarifFinding{
				RuleID:         ruleID,
				Level:          level,
				Message:        message,
				URL:            endpoint,
				Method:         result.Method,
				OriginalURLs:   []string{result.URL},
				RedirectChains: [][]string{result.RedirectChain},
			}
			seen[key] = &entry
		}
	}
	for _, entry := range seen {
		findings = append(findings, *entry)
	}
	return findings
}

func sarifForObservation(obs Observation, result ResultEntry) (string, string, string) {
	// sarifForObservation maps internal observations to SARIF rule metadata.
	switch obs.Type {
	case "header_missing":
		switch obs.Key {
		case "strict-transport-security":
			return "MISSING_HSTS", "warning", "Missing Strict-Transport-Security header."
		case "content-security-policy":
			return "MISSING_CSP", "warning", "Missing Content-Security-Policy header."
		case "x-frame-options":
			return "MISSING_X_FRAME_OPTIONS", "warning", "Missing X-Frame-Options header."
		case "x-content-type-options":
			return "MISSING_X_CONTENT_TYPE_OPTIONS", "warning", "Missing X-Content-Type-Options header."
		case "referrer-policy":
			return "MISSING_REFERRER_POLICY", "note", "Missing Referrer-Policy header."
		}
	case "http_not_https":
		return "HTTP_NOT_HTTPS", "warning", "Endpoint is served over HTTP (no TLS). HSTS is not applicable; consider serving over HTTPS."
	case "https_downgrade_redirect":
		return "HTTPS_DOWNGRADE_REDIRECT", "error", "HTTPS endpoint redirects to HTTP."
	case "missing_content_type":
		return "MISSING_CONTENT_TYPE", "warning", "Missing Content-Type header."
	case "missing_charset":
		return "MISSING_CHARSET", "note", "Content-Type is missing an explicit charset parameter for a text response."
	case "csp_missing_frame_ancestors":
		return "CSP_MISSING_FRAME_ANCESTORS", "warning", "Content-Security-Policy is missing frame-ancestors directive."
	case "missing_anti_embedding":
		return "MISSING_ANTI_EMBEDDING", "warning", "No CSP frame-ancestors or X-Frame-Options found."
	case "missing_coop":
		return "MISSING_COOP", "note", "Missing Cross-Origin-Opener-Policy (COOP) header (web_hardening profile)."
	case "missing_coep":
		return "MISSING_COEP", "note", "Missing Cross-Origin-Embedder-Policy (COEP) header (web_hardening profile)."
	case "missing_corp":
		return "MISSING_CORP", "note", "Missing Cross-Origin-Resource-Policy (CORP) header (web_hardening profile)."
	case "tls_cert_expires_soon":
		return "TLS_CERT_EXPIRES_SOON", "warning", "TLS certificate expires soon."
	}
	return "", "", ""
}

func sarifRules() []map[string]any {
	// sarifRules declares the full ruleset so results can reference IDs safely.
	var rules []map[string]any
	for _, ruleID := range allRuleIDs() {
		rules = append(rules, map[string]any{
			"id": ruleID,
			"shortDescription": map[string]any{
				"text": ruleDescription(ruleID),
			},
		})
	}
	return rules
}

func ruleDescription(ruleID string) string {
	switch ruleID {
	case "MISSING_HSTS":
		return "Missing Strict-Transport-Security header on HTTPS response."
	case "MISSING_CSP":
		return "Missing Content-Security-Policy header."
	case "MISSING_X_FRAME_OPTIONS":
		return "Missing X-Frame-Options header."
	case "MISSING_X_CONTENT_TYPE_OPTIONS":
		return "Missing X-Content-Type-Options header."
	case "MISSING_REFERRER_POLICY":
		return "Missing Referrer-Policy header."
	case "MISSING_CONTENT_TYPE":
		return "Missing Content-Type header."
	case "MISSING_CHARSET":
		return "Content-Type is missing an explicit charset parameter for a text response."
	case "CSP_MISSING_FRAME_ANCESTORS":
		return "Content-Security-Policy is missing frame-ancestors directive."
	case "MISSING_ANTI_EMBEDDING":
		return "No CSP frame-ancestors or X-Frame-Options found."
	case "MISSING_COOP":
		return "Missing Cross-Origin-Opener-Policy (COOP) header (web_hardening profile)."
	case "MISSING_COEP":
		return "Missing Cross-Origin-Embedder-Policy (COEP) header (web_hardening profile)."
	case "MISSING_CORP":
		return "Missing Cross-Origin-Resource-Policy (CORP) header (web_hardening profile)."
	case "HTTP_NOT_HTTPS":
		return "Endpoint is served over HTTP (no TLS)."
	case "HTTPS_DOWNGRADE_REDIRECT":
		return "HTTPS endpoint redirects to HTTP."
	case "TLS_CERT_EXPIRES_SOON":
		return "TLS certificate expires soon."
	default:
		return "Security observation."
	}
}

func ruleSeverity(ruleID string) string {
	switch ruleID {
	case "HTTPS_DOWNGRADE_REDIRECT":
		return "critical"
	case "MISSING_ANTI_EMBEDDING":
		return "critical"
	case "MISSING_HSTS":
		return "high"
	case "MISSING_CONTENT_TYPE":
		return "high"
	case "MISSING_CSP":
		return "medium"
	case "CSP_MISSING_FRAME_ANCESTORS":
		return "medium"
	case "MISSING_X_FRAME_OPTIONS":
		return "medium"
	case "HTTP_NOT_HTTPS":
		return "medium"
	case "TLS_CERT_EXPIRES_SOON":
		return "medium"
	case "MISSING_X_CONTENT_TYPE_OPTIONS":
		return "low"
	case "MISSING_REFERRER_POLICY":
		return "low"
	case "MISSING_CHARSET":
		return "low"
	case "MISSING_COOP", "MISSING_COEP", "MISSING_CORP":
		return "info"
	default:
		return "info"
	}
}

func sarifLevelForSeverity(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "note"
	}
}

func allRuleIDs() []string {
	return []string{
		"MISSING_HSTS",
		"MISSING_CSP",
		"MISSING_X_FRAME_OPTIONS",
		"MISSING_X_CONTENT_TYPE_OPTIONS",
		"MISSING_REFERRER_POLICY",
		"MISSING_CONTENT_TYPE",
		"MISSING_CHARSET",
		"CSP_MISSING_FRAME_ANCESTORS",
		"MISSING_ANTI_EMBEDDING",
		"MISSING_COOP",
		"MISSING_COEP",
		"MISSING_CORP",
		"HTTP_NOT_HTTPS",
		"HTTPS_DOWNGRADE_REDIRECT",
		"TLS_CERT_EXPIRES_SOON",
	}
}

func isTextLikeMediaType(contentType string) bool {
	// isTextLikeMediaType identifies content types that should declare charset.
	value := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.HasPrefix(value, "text/") {
		return true
	}
	switch value {
	case "application/xml", "application/javascript", "text/javascript":
		return true
	default:
		return false
	}
}

func hasCharset(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "charset=")
}

func buildTLSConfig(options TLSOptions) (*tls.Config, string, error) {
	// buildTLSConfig supports system, custom CA, and insecure modes.
	mode := "system"
	if options.InsecureSkipVerify {
		return &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         options.ServerName,
		}, "insecure", nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if options.CABundlePath != "" {
		pemData, err := os.ReadFile(options.CABundlePath)
		if err != nil {
			return nil, "", err
		}
		if ok := rootCAs.AppendCertsFromPEM(pemData); !ok {
			return nil, "", errors.New("failed to load CA bundle")
		}
		mode = "custom_ca"
	}

	return &tls.Config{
		RootCAs:    rootCAs,
		ServerName: options.ServerName,
	}, mode, nil
}

func tlsErrorReason(err error) string {
	// tlsErrorReason normalizes common TLS failures into stable strings.
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "tls: unknown authority"
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return "tls: hostname mismatch"
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		switch certInvalid.Reason {
		case x509.Expired:
			return "tls: certificate expired or not yet valid"
		default:
			return "tls: certificate invalid"
		}
	}
	return ""
}

func canonicalizeAttemptURL(parsed *url.URL, httpsPorts []int) *url.URL {
	// canonicalizeAttemptURL forces HTTPS for known TLS ports to avoid downgrade.
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	for _, httpsPort := range httpsPorts {
		if port == fmt.Sprintf("%d", httpsPort) {
			parsed.Scheme = "https"
			parsed.Host = fmt.Sprintf("%s:%s", parsed.Hostname(), port)
			return parsed
		}
	}
	return parsed
}

func cspHasFrameAncestors(csp string) bool {
	// cspHasFrameAncestors checks CSP policy for anti-embedding coverage.
	directives := strings.Split(csp, ";")
	for _, directive := range directives {
		value := strings.TrimSpace(directive)
		if value == "" {
			continue
		}
		parts := strings.Fields(value)
		if len(parts) == 0 {
			continue
		}
		if strings.EqualFold(parts[0], "frame-ancestors") {
			return true
		}
	}
	return false
}

func sarifResults(findings []sarifFinding, req ToolRequest) []map[string]any {
	// sarifResults builds result entries with fingerprints for diff stability.
	results := []map[string]any{}
	for _, finding := range findings {
		ruleID := finding.RuleID
		severity := ruleSeverity(ruleID)
		level := sarifLevelForSeverity(severity)
		results = append(results, map[string]any{
			"ruleId": ruleID,
			"level":  level,
			"message": map[string]any{
				"text": finding.Message,
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{
							"uri": finding.URL,
						},
					},
				},
			},
			"properties": map[string]any{
				"engagement_id":       req.EngagementID,
				"run_id":              req.RunID,
				"tool_name":           toolName,
				"tool_version":        toolVersion,
				"severity":            severity,
				"original_url":        firstOrEmpty(finding.OriginalURLs),
				"original_urls":       finding.OriginalURLs,
				"final_url":           finding.URL,
				"redirect_chain":      firstRedirectChain(finding.RedirectChains),
				"redirect_chains":     finding.RedirectChains,
				"finding_fingerprint": findingFingerprint(ruleID, finding.URL, finding.Method, req.Profile),
			},
			"partialFingerprints": map[string]any{
				"primary": findingFingerprint(ruleID, finding.URL, finding.Method, req.Profile),
			},
		})
	}
	return results
}

func buildNotifications(results []ResultEntry) []map[string]any {
	// buildNotifications emits unique error notifications for SARIF invocations.
	var notifications []map[string]any
	seen := map[string]bool{}
	for _, result := range results {
		if result.Error == "" || result.Error == "blocked" {
			continue
		}
		attempted := result.URL
		if attempted == "" {
			continue
		}
		attempted = canonicalAttemptURL(attempted)
		if seen[attempted] {
			continue
		}
		seen[attempted] = true
		notifications = append(notifications, map[string]any{
			"level": "warning",
			"message": map[string]any{
				"text": fmt.Sprintf("%s (url=%s)", result.Error, attempted),
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{
							"uri": attempted,
						},
					},
				},
			},
			"properties": map[string]any{
				"attempted_url": attempted,
			},
		})
	}
	return notifications
}

func canonicalAttemptURL(value string) string {
	// canonicalAttemptURL normalizes common HTTPS alternate ports for reporting.
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	port := parsed.Port()
	if port == "8443" || port == "8444" {
		parsed.Scheme = "https"
		if parsed.Hostname() != "" {
			parsed.Host = fmt.Sprintf("%s:%s", parsed.Hostname(), port)
		}
		return parsed.String()
	}
	return value
}

func validateSarifRules(sarif map[string]any) error {
	// validateSarifRules ensures every result references a declared rule.
	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) == 0 {
		return errors.New("sarif missing runs")
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules := []map[string]any{}
	if typed, ok := driver["rules"].([]map[string]any); ok {
		rules = typed
	} else if rawRules, ok := driver["rules"].([]any); ok {
		for _, raw := range rawRules {
			rules = append(rules, raw.(map[string]any))
		}
	} else {
		return errors.New("sarif rules not list")
	}
	ids := map[string]bool{}
	for _, rule := range rules {
		if id, ok := rule["id"].(string); ok {
			ids[id] = true
		}
	}
	results := []map[string]any{}
	if typed, ok := run["results"].([]map[string]any); ok {
		results = typed
	} else if rawResults, ok := run["results"].([]any); ok {
		for _, raw := range rawResults {
			results = append(results, raw.(map[string]any))
		}
	} else {
		return errors.New("sarif results not list")
	}
	for _, result := range results {
		id, _ := result["ruleId"].(string)
		if id == "" || !ids[id] {
			return errors.New("sarif ruleId missing from rules")
		}
	}
	return nil
}

func canonicalEndpoint(result ResultEntry) string {
	// canonicalEndpoint prefers final URL for dedupe when redirects exist.
	if result.FinalURL != "" {
		return canonicalizeURL(result.FinalURL)
	}
	return canonicalizeURL(result.URL)
}

func canonicalizeRedirectChain(chain []string) []string {
	if len(chain) == 0 {
		return []string{}
	}
	canon := make([]string, 0, len(chain))
	for _, entry := range chain {
		canon = append(canon, canonicalizeURL(entry))
	}
	return canon
}

func canonicalizeURL(raw string) string {
	// canonicalizeURL normalizes URLs for stable fingerprints and reporting.
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if scheme == "https" && port == "443" {
		port = ""
	}
	if scheme == "http" && port == "80" {
		port = ""
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	query := parsed.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0)
	for _, key := range keys {
		values := query[key]
		sort.Strings(values)
		for _, value := range values {
			pairs = append(pairs, url.QueryEscape(key)+"="+url.QueryEscape(value))
		}
	}
	rawQuery := strings.Join(pairs, "&")
	var hostport string
	if port != "" {
		hostport = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	} else {
		hostport = host
	}
	canonical := url.URL{
		Scheme:   scheme,
		Host:     hostport,
		Path:     path,
		RawQuery: rawQuery,
	}
	return canonical.String()
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstRedirectChain(chains [][]string) []string {
	if len(chains) == 0 {
		return []string{}
	}
	return chains[0]
}

func findingFingerprint(ruleID string, canonicalURL string, method string, profile string) string {
	// findingFingerprint uses rule + canonical endpoint so diffs survive re-runs.
	value := fmt.Sprintf("%s|%s|%s|%s|%s", toolName, ruleID, canonicalURL, strings.ToUpper(method), profile)
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)[:16]
}

func fingerprintsForResult(result ResultEntry, profile string) []string {
	// fingerprintsForResult returns a stable, sorted set of finding fingerprints.
	if len(result.Observations) == 0 {
		return []string{}
	}
	endpoint := canonicalEndpoint(result)
	seen := map[string]struct{}{}
	for _, obs := range result.Observations {
		ruleID, _, _, ok := observationToRule(obs, result)
		if !ok {
			continue
		}
		fingerprint := findingFingerprint(ruleID, endpoint, result.Method, profile)
		seen[fingerprint] = struct{}{}
	}
	results := make([]string, 0, len(seen))
	for value := range seen {
		results = append(results, value)
	}
	sort.Strings(results)
	return results
}

func observationToRule(obs Observation, result ResultEntry) (string, string, string, bool) {
	// observationToRule filters out observations that don't apply to the final scheme.
	if obs.Type == "header_missing" && obs.Key == "strict-transport-security" {
		final := finalScheme(result)
		if final != "https" || result.TLS == nil {
			return "", "", "", false
		}
	}
	if obs.Type == "http_not_https" {
		final := finalScheme(result)
		if final != "http" || result.TLS != nil {
			return "", "", "", false
		}
	}
	ruleID, level, message := sarifForObservation(obs, result)
	if ruleID == "" {
		return "", "", "", false
	}
	return ruleID, level, message, true
}

func finalScheme(result ResultEntry) string {
	if result.FinalURL == "" {
		return ""
	}
	parsed, err := url.Parse(result.FinalURL)
	if err != nil {
		return ""
	}
	return parsed.Scheme
}
