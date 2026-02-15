package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

var toolVersion = "dev"

type ToolRequest struct {
	ToolName            string                 `json:"tool_name"`
	EngagementID        string                 `json:"engagement_id"`
	RunID               string                 `json:"run_id"`
	Scope               map[string]interface{} `json:"scope"`
	DryRun              bool                   `json:"dry_run"`
	TimeoutMS           int                    `json:"timeout_ms"`
	PerAttemptTimeoutMS int                    `json:"per_attempt_timeout_ms"`
	RateLimit           RateLimit              `json:"rate_limit"`
	Input               ProbeInput             `json:"input"`
}

type RateLimit struct {
	RPS         float64 `json:"rps"`
	Burst       int     `json:"burst"`
	Concurrency int     `json:"concurrency"`
}

type ProbeInput struct {
	Targets  []Target `json:"targets"`
	Ports    []int    `json:"ports"`
	Protocol string   `json:"protocol"`
}

type Target struct {
	Host string `json:"host"`
}

type ToolResponse struct {
	OK            bool           `json:"ok"`
	BlockedReason *string        `json:"blocked_reason"`
	Findings      []Finding      `json:"findings"`
	Evidence      []Evidence     `json:"evidence"`
	Metrics       map[string]any `json:"metrics"`
	RawRedacted   map[string]any `json:"raw_redacted"`
	ToolName      string         `json:"tool_name"`
	ToolVersion   string         `json:"tool_version"`
}

type Evidence struct {
	ID            string         `json:"id"`
	Timestamp     string         `json:"timestamp"`
	Type          string         `json:"type"`
	Target        string         `json:"target"`
	Data          map[string]any `json:"data"`
	SchemaVersion string         `json:"schema_version"`
	EngagementID  string         `json:"engagement_id"`
	RunID         string         `json:"run_id"`
	ToolName      string         `json:"tool_name"`
	ToolVersion   string         `json:"tool_version"`
	Status        string         `json:"status"`
	DurationMS    int64          `json:"duration_ms"`
}

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Target      string   `json:"target"`
	EvidenceIDs []string `json:"evidence_ids"`
	Summary     string   `json:"summary"`
	Timestamp   string   `json:"timestamp"`
}

func main() {
	// main reads a ToolRequest from stdin and writes a ToolResponse to stdout so
	// the Python orchestration layer can treat the probe as a pure function.
	const toolName = "probe"
	const schemaVersion = "1.0.0"

	reader := bufio.NewReader(os.Stdin)
	var req ToolRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		writeError("invalid_request")
		return
	}

	if req.DryRun {
		reason := "dry_run"
		writeResponse(ToolResponse{OK: false, BlockedReason: &reason, ToolName: toolName, ToolVersion: toolVersion})
		return
	}

	// Hard cap ports to avoid unbounded scans from misconfigured inputs.
	if len(req.Input.Ports) > 100 {
		reason := "port_list_too_large"
		writeResponse(ToolResponse{OK: false, BlockedReason: &reason, ToolName: toolName, ToolVersion: toolVersion})
		return
	}

	start := time.Now()
	perAttempt := req.PerAttemptTimeoutMS
	if perAttempt <= 0 {
		perAttempt = req.TimeoutMS
	}
	timeout := time.Duration(perAttempt) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	var findings []Finding
	var evidence []Evidence
	attempted := 0
	openCount := 0

	var ticker *time.Ticker
	// Time-based limiter keeps request pacing stable without extra goroutines.
	if req.RateLimit.RPS > 0 {
		interval := time.Duration(float64(time.Second) / req.RateLimit.RPS)
		if interval > 0 {
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		}
	}

	for _, target := range req.Input.Targets {
		for _, port := range req.Input.Ports {
			if ticker != nil {
				<-ticker.C
			}
			attempted++
			addr := fmt.Sprintf("%s:%d", target.Host, port)
			attemptStart := time.Now()
			conn, err := net.DialTimeout(req.Input.Protocol, addr, timeout)
			durationMS := time.Since(attemptStart).Milliseconds()
			status := "success"
			data := map[string]any{
				"protocol": req.Input.Protocol,
				"port":     port,
			}
			if err != nil {
				status = "error"
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					status = "timeout"
				}
				data["error"] = err.Error()
			} else {
				_ = conn.Close()
				openCount++
			}

			ts := time.Now().UTC().Format(time.RFC3339Nano)
			evID := fmt.Sprintf("evi-%d", time.Now().UnixNano())
			evidence = append(evidence, Evidence{
				ID:            evID,
				Timestamp:     ts,
				Type:          "tcp_connect",
				Target:        addr,
				Data:          data,
				SchemaVersion: schemaVersion,
				EngagementID:  req.EngagementID,
				RunID:         req.RunID,
				ToolName:      toolName,
				ToolVersion:   toolVersion,
				Status:        status,
				DurationMS:    durationMS,
			})

			if err != nil {
				continue
			}

			findings = append(findings, Finding{
				ID:          fmt.Sprintf("fnd-%d", time.Now().UnixNano()),
				Title:       "Open TCP port",
				Severity:    "low",
				Target:      addr,
				EvidenceIDs: []string{evID},
				Summary:     "TCP connection succeeded.",
				Timestamp:   ts,
			})
		}
	}

	metrics := map[string]any{
		"attempted":  attempted,
		"open_count": openCount,
		"elapsed_ms": time.Since(start).Milliseconds(),
	}

	writeResponse(ToolResponse{
		OK:          true,
		Findings:    findings,
		Evidence:    evidence,
		Metrics:     metrics,
		RawRedacted: map[string]any{},
		ToolName:    toolName,
		ToolVersion: toolVersion,
	})
}

func writeError(reason string) {
	const toolName = "probe"
	writeResponse(ToolResponse{OK: false, BlockedReason: &reason, ToolName: toolName, ToolVersion: toolVersion})
}

func writeResponse(resp ToolResponse) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}
