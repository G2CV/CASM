package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutOfScopeBlockedNoNetwork(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := ToolRequest{
		EngagementID: "eng-1",
		RunID:        "run-1",
		DryRun:       false,
		Scope: Scope{
			AllowedDomains:   []string{"example.com"},
			AllowedIPs:       []string{"192.0.2.0/24"},
			AllowedPorts:     []int{80},
			AllowedProtocols: []string{"http"},
		},
		Targets:  []Target{{URL: server.URL, Method: "HEAD"}},
		Limits:   Limits{MaxConcurrency: 1, RPS: 0, TimeoutMS: 1000, MaxRedirects: 1, MaxBodyBytes: 1024, TLSExpiryDays: 30},
		Evidence: EvidenceOut{JSONLPath: path},
		Sarif:    SarifOut{Enabled: false},
	}

	resp := run(req)
	if resp.Summary.Blocked != 1 {
		t.Fatalf("expected blocked summary")
	}
	if hits != 0 {
		t.Fatalf("expected no network calls")
	}
	items := readEvidence(t, path)
	assertEventType(t, items, "http_blocked")
}

func TestHeadFallbackToGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	resp := run(req)
	if resp.Results[0].StatusCode != http.StatusOK {
		t.Fatalf("expected 200 status")
	}
	items := readEvidence(t, path)
	assertEventType(t, items, "http_response")
}

func TestRedirectLoopCapped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	req.Limits.MaxRedirects = 1
	resp := run(req)
	if resp.Results[0].Error == "" {
		t.Fatalf("expected redirect error")
	}
	items := readEvidence(t, path)
	assertEventType(t, items, "http_error")
}

func TestHTTPNoHSTSNotEmitted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	resp := run(req)
	obs := resp.Results[0].Observations
	if hasObservation(obs, "header_missing", "strict-transport-security") {
		t.Fatalf("unexpected HSTS observation on HTTP")
	}
	if !hasObservation(obs, "http_not_https", "") {
		t.Fatalf("expected http_not_https observation")
	}
}

func TestHTTPSMissingHSTS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if !hasObservation(result.Observations, "header_missing", "strict-transport-security") {
		t.Fatalf("expected HSTS missing observation on HTTPS")
	}
}

func TestHTTPSDowngradeRedirect(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", httpServer.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer httpsServer.Close()

	client := httpsServer.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(httpsServer.URL, path)
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, httpsServer.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if !hasObservation(result.Observations, "https_downgrade_redirect", "") {
		t.Fatalf("expected https_downgrade_redirect observation")
	}
	if hasObservation(result.Observations, "header_missing", "strict-transport-security") {
		t.Fatalf("unexpected HSTS observation after downgrade")
	}
}

func TestMissingContentType_EmitsSarif(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifHasResult(parsed, "MISSING_CONTENT_TYPE") {
		t.Fatalf("expected MISSING_CONTENT_TYPE")
	}
}

func TestHasCharset_NoFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "MISSING_CONTENT_TYPE") {
		t.Fatalf("unexpected MISSING_CONTENT_TYPE")
	}
	if sarifHasResult(parsed, "MISSING_CHARSET") {
		t.Fatalf("unexpected MISSING_CHARSET")
	}
}

func TestTextLikeMissingCharset_EmitsSarif(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifHasResult(parsed, "MISSING_CHARSET") {
		t.Fatalf("expected MISSING_CHARSET")
	}
}

func TestNonTextLike_NoCharset_NoFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "MISSING_CHARSET") {
		t.Fatalf("unexpected MISSING_CHARSET")
	}
}

func TestCspHasFrameAncestors_NoFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "CSP_MISSING_FRAME_ANCESTORS") {
		t.Fatalf("unexpected CSP_MISSING_FRAME_ANCESTORS")
	}
	if sarifHasResult(parsed, "MISSING_ANTI_EMBEDDING") {
		t.Fatalf("unexpected MISSING_ANTI_EMBEDDING")
	}
}

func TestCspMissingFrameAncestors_EmitsCspFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifHasResult(parsed, "CSP_MISSING_FRAME_ANCESTORS") {
		t.Fatalf("expected CSP_MISSING_FRAME_ANCESTORS")
	}
	if !sarifHasResult(parsed, "MISSING_ANTI_EMBEDDING") {
		t.Fatalf("expected MISSING_ANTI_EMBEDDING")
	}
}

func TestXfoOnly_NoMissingAntiEmbedding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "MISSING_ANTI_EMBEDDING") {
		t.Fatalf("unexpected MISSING_ANTI_EMBEDDING")
	}
	if sarifHasResult(parsed, "CSP_MISSING_FRAME_ANCESTORS") {
		t.Fatalf("unexpected CSP_MISSING_FRAME_ANCESTORS")
	}
}

func TestCspNoFrameAncestors_ButXfoPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifHasResult(parsed, "CSP_MISSING_FRAME_ANCESTORS") {
		t.Fatalf("expected CSP_MISSING_FRAME_ANCESTORS")
	}
	if sarifHasResult(parsed, "MISSING_ANTI_EMBEDDING") {
		t.Fatalf("unexpected MISSING_ANTI_EMBEDDING")
	}
}

func TestCrossOriginIsolation_ProfileOff_NoFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Profile = "baseline"
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "MISSING_COOP") || sarifHasResult(parsed, "MISSING_COEP") || sarifHasResult(parsed, "MISSING_CORP") {
		t.Fatalf("unexpected cross-origin isolation findings")
	}
}

func TestCrossOriginIsolation_ProfileOn_EmitsFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Profile = "web_hardening"
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifHasResult(parsed, "MISSING_COOP") || !sarifHasResult(parsed, "MISSING_COEP") || !sarifHasResult(parsed, "MISSING_CORP") {
		t.Fatalf("expected cross-origin isolation findings")
	}
}

func TestCrossOriginIsolation_ProfileOn_NoFindingsWhenPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Profile = "web_hardening"
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "MISSING_COOP") || sarifHasResult(parsed, "MISSING_COEP") || sarifHasResult(parsed, "MISSING_CORP") {
		t.Fatalf("unexpected cross-origin isolation findings")
	}
}

func TestCrossOriginIsolation_NotHtml_NoFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Profile = "web_hardening"
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if sarifHasResult(parsed, "MISSING_COOP") || sarifHasResult(parsed, "MISSING_COEP") || sarifHasResult(parsed, "MISSING_CORP") {
		t.Fatalf("unexpected cross-origin isolation findings")
	}
}

func TestEvidenceCapturesContentTypeHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	_ = run(req)

	items := readEvidence(t, path)
	response := findEvidenceByType(t, items, "http_response")
	headers, ok := response["data"].(map[string]any)["headers"].(map[string]any)
	if !ok {
		t.Fatalf("missing headers in evidence")
	}
	value, ok := headers["content-type"].(string)
	if !ok {
		t.Fatalf("missing content-type header")
	}
	if value != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content-type value: %s", value)
	}
}

func TestObservedHeadersInStdout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	resp := run(req)
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	value := resp.Results[0].ObservedHeaders["content-type"]
	if value != "text/html; charset=utf-8" {
		t.Fatalf("unexpected observed content-type: %s", value)
	}
}

func TestTLSUnknownAuthorityFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	resp := run(req)
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	if !strings.Contains(resp.Results[0].Error, "unknown authority") {
		t.Fatalf("expected unknown authority error, got: %s", resp.Results[0].Error)
	}
}

func TestTLSCustomCAAllowsConnection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	caPath := writeServerCert(t, server)
	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	req.TLS.CABundlePath = caPath
	resp := run(req)
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	if resp.Results[0].Error != "" {
		t.Fatalf("expected success, got error: %s", resp.Results[0].Error)
	}
}

func TestTLSInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	req.TLS.InsecureSkipVerify = true
	resp := run(req)
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	if resp.Results[0].Error != "" {
		t.Fatalf("expected success, got error: %s", resp.Results[0].Error)
	}
	if resp.Results[0].TLSMode != "insecure" {
		t.Fatalf("expected tls_mode insecure")
	}
}

func TestTLSHostnameMismatchUnlessOverridden(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	caPath := writeServerCert(t, server)
	path := tempFile(t, "evidence.jsonl")
	req := baseRequest(server.URL, path)
	req.TLS.CABundlePath = caPath
	req.TLS.ServerName = "not-example.invalid"
	parsed := mustParseURL(t, server.URL)
	config, _, err := buildTLSConfig(req.TLS)
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	client := buildClient(2000, config)
	_, err = executeRequest(req, client, "HEAD", parsed)
	if err == nil || tlsErrorReason(err) != "tls: hostname mismatch" {
		t.Fatalf("expected hostname mismatch, got: %v", err)
	}

	req.TLS.ServerName = parsed.Hostname()
	config, _, err = buildTLSConfig(req.TLS)
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	client = buildClient(2000, config)
	_, err = executeRequest(req, client, "HEAD", parsed)
	if err != nil {
		t.Fatalf("expected success with server name override, got: %v", err)
	}
}

func TestTLSCertExpiresSoon(t *testing.T) {
	cert := x509.Certificate{
		NotAfter: time.Now().Add(24 * time.Hour),
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{&cert}}
	if !tlsExpiresSoon(state, 30) {
		t.Fatalf("expected cert to be considered expiring soon")
	}
}

func TestSarifOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	resp := run(req)
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	if err := writeSarif(req, resp.Results); err != nil {
		t.Fatalf("write sarif: %v", err)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed reading sarif: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	if parsed["version"].(string) != "2.1.0" {
		t.Fatalf("unexpected sarif version")
	}
	if sarifHasResult(parsed, "MISSING_HSTS") {
		t.Fatalf("did not expect MISSING_HSTS result for HTTP")
	}
	if !sarifHasResult(parsed, "HTTP_NOT_HTTPS") {
		t.Fatalf("expected HTTP_NOT_HTTPS result")
	}
	if !sarifResultsInRules(parsed) {
		t.Fatalf("sarif results missing rule metadata")
	}
	if !sarifHasOriginalURL(parsed, server.URL) {
		t.Fatalf("expected original_url property")
	}
}

func TestSarifEmptyResultsIsArray(t *testing.T) {
	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest("https://example.com", path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath

	if err := writeSarif(req, []ResultEntry{}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed reading sarif: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one sarif run")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid sarif run structure")
	}
	if _, ok := run["results"].([]any); !ok {
		t.Fatalf("expected results to be an array")
	}
}

func TestFindingFingerprintMatchesEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	_ = run(req)

	items := readEvidence(t, path)
	response := findEvidenceByType(t, items, "http_response")
	data, ok := response["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing response data")
	}
	fingerprints, ok := data["finding_fingerprints"].([]any)
	if !ok || len(fingerprints) == 0 {
		t.Fatalf("missing finding_fingerprints")
	}

	parsed := readSarif(t, sarifPath)
	results := sarifResultsList(parsed)
	if len(results) == 0 {
		t.Fatalf("expected sarif results")
	}
	primary := results[0]["partialFingerprints"].(map[string]any)["primary"].(string)
	if len(primary) != 16 {
		t.Fatalf("expected 16-char fingerprint")
	}
	matched := false
	for _, raw := range fingerprints {
		if primary == raw.(string) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("fingerprint missing from evidence list")
	}
}

func TestSarifSeverityMatchesRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	_ = run(req)

	parsed := readSarif(t, sarifPath)
	results := sarifResultsList(parsed)
	if len(results) == 0 {
		t.Fatalf("expected sarif results")
	}
	severity := results[0]["properties"].(map[string]any)["severity"].(string)
	level := results[0]["level"].(string)
	if severity == "high" && level != "error" {
		t.Fatalf("expected high severity to map to error")
	}
	if severity == "medium" && level != "warning" {
		t.Fatalf("expected medium severity to map to warning")
	}
}

func TestCanonicalizeURL(t *testing.T) {
	cases := map[string]string{
		"https://Example.com:443/":          "https://example.com/",
		"http://Example.com:80/path/":       "http://example.com/path",
		"https://example.com/page/?b=2&a=1": "https://example.com/page?a=1&b=2",
		"https://example.com/page#section":  "https://example.com/page",
		"https://example.com":               "https://example.com/",
		"https://example.com/Case/Path/":    "https://example.com/Case/Path",
		"https://[2001:db8::1]:443/health":  "https://[2001:db8::1]/health",
	}
	for input, expected := range cases {
		if got := canonicalizeURL(input); got != expected {
			t.Fatalf("canonicalizeURL(%q)=%q, want %q", input, got, expected)
		}
	}
}

func TestSarifIncludesMissingHSTSForHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 2 * time.Second

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath

	result, err := executeRequest(req, client, "HEAD", mustParseURL(t, server.URL))
	if err != nil {
		t.Fatalf("executeRequest failed: %v", err)
	}
	if err := writeSarif(req, []ResultEntry{result}); err != nil {
		t.Fatalf("write sarif: %v", err)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed reading sarif: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	if !hasSarifRule(parsed, "MISSING_HSTS") {
		t.Fatalf("expected MISSING_HSTS for HTTPS")
	}
}

func TestSarifRuleDictionaryIncludesContentTypeRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest(server.URL, path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	resp := run(req)
	if err := writeSarif(req, resp.Results); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifRuleHasDescription(parsed, "MISSING_CONTENT_TYPE") {
		t.Fatalf("missing rule description for MISSING_CONTENT_TYPE")
	}
	if !sarifRuleHasDescription(parsed, "MISSING_CHARSET") {
		t.Fatalf("missing rule description for MISSING_CHARSET")
	}
}

func TestSarifNotificationsForFailures(t *testing.T) {
	path := tempFile(t, "evidence.jsonl")
	sarifPath := tempFile(t, "results.sarif")
	req := baseRequest("https://example.com", path)
	req.Sarif.Enabled = true
	req.Sarif.Path = sarifPath
	results := []ResultEntry{{URL: "https://example.com", Error: "tls: unknown authority"}}
	if err := writeSarif(req, results); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	parsed := readSarif(t, sarifPath)
	if !sarifHasNotification(parsed, "https://example.com") {
		t.Fatalf("expected notification for failed attempt")
	}
	if !sarifNotificationMessageHasURL(parsed, "https://example.com") {
		t.Fatalf("expected notification message to include attempted url")
	}
}

func baseRequest(url string, evidencePath string) ToolRequest {
	parsed, _ := urlpkg.Parse(url)
	port := 80
	if parsed != nil {
		if parsed.Port() != "" {
			if p, err := net.LookupPort("tcp", parsed.Port()); err == nil {
				port = p
			}
		} else if parsed.Scheme == "https" {
			port = 443
		}
	}
	return ToolRequest{
		EngagementID: "eng-1",
		RunID:        "run-1",
		DryRun:       false,
		Profile:      "baseline",
		TLS:          TLSOptions{},
		Scope: Scope{
			AllowedDomains:   []string{"*"},
			AllowedIPs:       []string{"127.0.0.0/8", "::1/128"},
			AllowedPorts:     []int{port},
			AllowedProtocols: []string{"http", "https"},
		},
		Targets:  []Target{{URL: url, Method: "HEAD"}},
		Limits:   Limits{MaxConcurrency: 1, RPS: 0, TimeoutMS: 1000, MaxRedirects: 2, MaxBodyBytes: 1024, TLSExpiryDays: 30},
		Evidence: EvidenceOut{JSONLPath: evidencePath},
		Sarif:    SarifOut{Enabled: false},
	}
}

func readEvidence(t *testing.T, path string) []map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var items []map[string]any
	for _, line := range lines {
		var item map[string]any
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			t.Fatalf("invalid evidence json: %v", err)
		}
		if item["id"] == nil || item["engagement_id"] == nil || item["run_id"] == nil || item["tool_name"] == nil || item["tool_version"] == nil || item["schema_version"] == nil {
			t.Fatalf("missing required fields")
		}
		items = append(items, item)
	}
	return items
}

func mustParseURL(t *testing.T, value string) *urlpkg.URL {
	parsed, err := urlpkg.Parse(value)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return parsed
}

func hasObservation(observations []Observation, typ string, key string) bool {
	for _, obs := range observations {
		if obs.Type == typ {
			if key == "" || obs.Key == key {
				return true
			}
		}
	}
	return false
}

func hasSarifRule(parsed map[string]any, ruleID string) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok {
		return false
	}
	for _, item := range rules {
		rule := item.(map[string]any)
		if rule["id"] == ruleID {
			return true
		}
	}
	return false
}

func sarifResultsInRules(parsed map[string]any) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rulesRaw, ok := driver["rules"].([]any)
	if !ok {
		return false
	}
	ids := map[string]bool{}
	for _, item := range rulesRaw {
		rule := item.(map[string]any)
		if id, ok := rule["id"].(string); ok {
			ids[id] = true
		}
	}
	results, ok := run["results"].([]any)
	if !ok {
		return false
	}
	for _, raw := range results {
		result := raw.(map[string]any)
		id, _ := result["ruleId"].(string)
		if id == "" || !ids[id] {
			return false
		}
	}
	return true
}

func sarifHasResult(parsed map[string]any, ruleID string) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok {
		return false
	}
	for _, raw := range results {
		result := raw.(map[string]any)
		if result["ruleId"] == ruleID {
			return true
		}
	}
	return false
}

func sarifResultsList(parsed map[string]any) []map[string]any {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return []map[string]any{}
	}
	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok {
		return []map[string]any{}
	}
	items := make([]map[string]any, 0, len(results))
	for _, raw := range results {
		items = append(items, raw.(map[string]any))
	}
	return items
}

func sarifHasOriginalURL(parsed map[string]any, url string) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok {
		return false
	}
	for _, raw := range results {
		result := raw.(map[string]any)
		props, ok := result["properties"].(map[string]any)
		if !ok {
			continue
		}
		if props["original_url"] == url {
			return true
		}
	}
	return false
}

func sarifHasNotification(parsed map[string]any, url string) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	invocations, ok := run["invocations"].([]any)
	if !ok || len(invocations) == 0 {
		return false
	}
	invocation := invocations[0].(map[string]any)
	notifications, ok := invocation["toolExecutionNotifications"].([]any)
	if !ok {
		return false
	}
	for _, raw := range notifications {
		note := raw.(map[string]any)
		locations, ok := note["locations"].([]any)
		if !ok || len(locations) == 0 {
			continue
		}
		loc := locations[0].(map[string]any)
		phys := loc["physicalLocation"].(map[string]any)
		artifact := phys["artifactLocation"].(map[string]any)
		if artifact["uri"] == url {
			return true
		}
	}
	return false
}

func sarifNotificationMessageHasURL(parsed map[string]any, url string) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	invocations, ok := run["invocations"].([]any)
	if !ok || len(invocations) == 0 {
		return false
	}
	invocation := invocations[0].(map[string]any)
	notifications, ok := invocation["toolExecutionNotifications"].([]any)
	if !ok {
		return false
	}
	for _, raw := range notifications {
		note := raw.(map[string]any)
		message := note["message"].(map[string]any)
		text, _ := message["text"].(string)
		if strings.Contains(text, url) {
			return true
		}
	}
	return false
}

func sarifRuleHasDescription(parsed map[string]any, ruleID string) bool {
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		return false
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok {
		return false
	}
	for _, raw := range rules {
		rule := raw.(map[string]any)
		if rule["id"] == ruleID {
			if desc, ok := rule["shortDescription"].(map[string]any); ok {
				if text, ok := desc["text"].(string); ok {
					return text != ""
				}
			}
		}
	}
	return false
}

func findEvidenceByType(t *testing.T, items []map[string]any, eventType string) map[string]any {
	for _, item := range items {
		if item["type"] == eventType {
			return item
		}
	}
	t.Fatalf("missing evidence type %s", eventType)
	return nil
}

func readSarif(t *testing.T, path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading sarif: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	return parsed
}

func assertEventType(t *testing.T, items []map[string]any, eventType string) {
	for _, item := range items {
		if item["type"] == eventType {
			return
		}
	}
	t.Fatalf("expected event type %s", eventType)
}

func tempFile(t *testing.T, name string) string {
	dir := t.TempDir()
	return filepath.Join(dir, name)
}

func writeServerCert(t *testing.T, server *httptest.Server) string {
	cert := server.TLS.Certificates[0]
	if len(cert.Certificate) == 0 {
		t.Fatalf("missing server cert")
	}
	path := tempFile(t, "ca.pem")
	pemData := pemEncode(cert.Certificate[0])
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}
	return path
}

func pemEncode(derBytes []byte) []byte {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	return pem.EncodeToMemory(block)
}
