package main

import "testing"

func TestNormalizeDomains(t *testing.T) {
	input := []string{"Example.com", "example.com.", "", "api.example.com"}
	got := normalizeDomains(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(got))
	}
	if got[0] != "api.example.com" || got[1] != "example.com" {
		t.Fatalf("unexpected domains: %v", got)
	}
}

func TestFilterByDepth(t *testing.T) {
	domain := "example.com"
	values := []string{"api.example.com", "dev.api.example.com", "example.com"}
	filtered := filterByDepth(domain, values, 1)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 values, got %d", len(filtered))
	}
	if withinDepth(domain, "dev.api.example.com", 1) {
		t.Fatalf("expected depth check to fail")
	}
	if !withinDepth(domain, "api.example.com", 1) {
		t.Fatalf("expected api.example.com to be depth 1")
	}
}

func TestDiscoveryKeyStable(t *testing.T) {
	item := Discovery{Subdomain: "api.example.com", RecordType: "A", Values: []string{"2.2.2.2", "1.1.1.1"}}
	key := discoveryKey(item)
	if key != "api.example.com|A|1.1.1.1,2.2.2.2" {
		t.Fatalf("unexpected key: %s", key)
	}
}
