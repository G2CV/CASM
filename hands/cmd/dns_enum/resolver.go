package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver struct {
	client  *dns.Client
	servers []string
	timeout time.Duration
}

func NewDNSResolver(timeout time.Duration, servers []string) *DNSResolver {
	// NewDNSResolver prefers explicit servers, then system resolvers, then a safe fallback.
	resolved := normalizeServers(servers)
	if len(resolved) == 0 {
		resolved = loadSystemServers()
	}
	if len(resolved) == 0 {
		resolved = []string{"8.8.8.8:53"}
	}
	return &DNSResolver{
		client:  &dns.Client{Timeout: timeout},
		servers: resolved,
		timeout: timeout,
	}
}

type DNSAnswer struct {
	Values []string
	Rcode  int
}

func (r *DNSResolver) Query(name string, qtype uint16) (DNSAnswer, time.Duration, error) {
	// Query performs a single DNS lookup using the first configured resolver.
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	server := r.servers[0]
	start := time.Now()
	response, _, err := r.client.Exchange(msg, server)
	duration := time.Since(start)
	if err != nil {
		return DNSAnswer{}, duration, err
	}
	if response == nil {
		return DNSAnswer{}, duration, errors.New("empty dns response")
	}
	values := extractAnswers(response, qtype)
	return DNSAnswer{Values: values, Rcode: response.Rcode}, duration, nil
}

func extractAnswers(msg *dns.Msg, qtype uint16) []string {
	var values []string
	for _, answer := range msg.Answer {
		switch record := answer.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				values = append(values, record.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				values = append(values, record.AAAA.String())
			}
		case *dns.CNAME:
			if qtype == dns.TypeCNAME {
				values = append(values, strings.TrimSuffix(record.Target, "."))
			}
		case *dns.MX:
			if qtype == dns.TypeMX {
				values = append(values, strings.TrimSuffix(record.Mx, "."))
			}
		case *dns.TXT:
			if qtype == dns.TypeTXT {
				values = append(values, strings.Join(record.Txt, " "))
			}
		case *dns.SRV:
			if qtype == dns.TypeSRV {
				values = append(values, strings.TrimSuffix(record.Target, "."))
			}
		}
	}
	return values
}

func queryWithRetry(ctx context.Context, resolver *DNSResolver, name string, qtype uint16) (DNSAnswer, time.Duration, error) {
	// queryWithRetry retries transient DNS failures with exponential backoff.
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		answer, duration, err := resolver.Query(name, qtype)
		if err == nil {
			return answer, duration, nil
		}
		if ctx.Err() != nil {
			return DNSAnswer{}, duration, ctx.Err()
		}
		if attempt == 2 {
			return DNSAnswer{}, duration, err
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return DNSAnswer{}, 0, errors.New("dns query failed")
}

func normalizeServers(servers []string) []string {
	// normalizeServers ensures host:port formatting and dedupes entries.
	var resolved []string
	seen := map[string]bool{}
	for _, server := range servers {
		value := strings.TrimSpace(server)
		if value == "" {
			continue
		}
		if !strings.Contains(value, ":") {
			value = net.JoinHostPort(value, "53")
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		resolved = append(resolved, value)
	}
	return resolved
}

func loadSystemServers() []string {
	// loadSystemServers reads resolvers from /etc/resolv.conf when available.
	servers := []string{}
	if conf, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		for _, server := range conf.Servers {
			servers = append(servers, net.JoinHostPort(server, conf.Port))
		}
	}
	return servers
}
