package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func queryCrtSh(domain string, timeout time.Duration) ([]string, error) {
	// queryCrtSh fetches certificate transparency data for passive discovery.
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "casm-dns-enum/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, entry := range entries {
		parts := strings.Split(entry.NameValue, "\n")
		for _, value := range parts {
			value = strings.ToLower(strings.TrimSpace(value))
			value = strings.TrimPrefix(value, "*.")
			value = strings.TrimSuffix(value, ".")
			if value == "" {
				continue
			}
			if !strings.HasSuffix(value, domain) {
				continue
			}
			if seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out, nil
}
