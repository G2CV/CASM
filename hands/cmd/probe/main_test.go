package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
)

func TestMainInvalidRequest(t *testing.T) {
	resp := runMainWithInput(t, []byte("not-json"))
	if resp.OK {
		t.Fatalf("expected ok=false")
	}
	if resp.BlockedReason == nil || *resp.BlockedReason != "invalid_request" {
		t.Fatalf("expected blocked reason invalid_request")
	}
}

func TestMainDryRunBlocked(t *testing.T) {
	req := baseRequest()
	req.DryRun = true
	resp := runMain(t, req)
	if resp.OK {
		t.Fatalf("expected ok=false")
	}
	if resp.BlockedReason == nil || *resp.BlockedReason != "dry_run" {
		t.Fatalf("expected blocked reason dry_run")
	}
}

func TestMainPortListTooLarge(t *testing.T) {
	req := baseRequest()
	for i := 0; i < 101; i++ {
		req.Input.Ports = append(req.Input.Ports, 10000+i)
	}
	resp := runMain(t, req)
	if resp.OK {
		t.Fatalf("expected ok=false")
	}
	if resp.BlockedReason == nil || *resp.BlockedReason != "port_list_too_large" {
		t.Fatalf("expected blocked reason port_list_too_large")
	}
}

func TestMainSuccessfulProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	req := baseRequest()
	req.Input.Targets = []Target{{Host: "127.0.0.1"}}
	req.Input.Ports = []int{addr.Port}
	req.Input.Protocol = "tcp"

	acceptDone := make(chan struct{})
	go func() {
		if conn, err := listener.Accept(); err == nil {
			_ = conn.Close()
		}
		close(acceptDone)
	}()

	resp := runMain(t, req)
	<-acceptDone

	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if len(resp.Evidence) != 1 {
		t.Fatalf("expected 1 evidence entry")
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if resp.Metrics["attempted"].(float64) != 1 {
		t.Fatalf("expected attempted=1")
	}
	if resp.Metrics["open_count"].(float64) != 1 {
		t.Fatalf("expected open_count=1")
	}
	if resp.Evidence[0].Status != "success" {
		t.Fatalf("expected success status")
	}
	if resp.Evidence[0].Type != "tcp_connect" {
		t.Fatalf("expected tcp_connect evidence type")
	}
}

func baseRequest() ToolRequest {
	return ToolRequest{
		ToolName:     "probe",
		EngagementID: "eng-1",
		RunID:        "run-1",
		DryRun:       false,
		TimeoutMS:    500,
		Input: ProbeInput{
			Targets:  []Target{{Host: "127.0.0.1"}},
			Ports:    []int{80},
			Protocol: "tcp",
		},
	}
}

func runMain(t *testing.T, req ToolRequest) ToolResponse {
	t.Helper()
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return runMainWithInput(t, payload)
}

func runMainWithInput(t *testing.T, input []byte) ToolResponse {
	t.Helper()
	origIn := os.Stdin
	origOut := os.Stdout

	inReader, inWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin: %v", err)
	}
	outReader, outWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}

	os.Stdin = inReader
	os.Stdout = outWriter
	t.Cleanup(func() {
		os.Stdin = origIn
		os.Stdout = origOut
	})

	go func() {
		_, _ = inWriter.Write(input)
		_ = inWriter.Close()
	}()

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, outReader)
		close(done)
	}()

	main()
	_ = outWriter.Close()
	<-done

	var resp ToolResponse
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}
