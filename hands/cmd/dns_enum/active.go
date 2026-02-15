package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type queryJob struct {
	domain          string
	subdomain       string
	recordType      string
	source          string
	discoveryMethod string
}

type axfrRecord struct {
	name   string
	rtype  string
	values []string
}

func resolveDomains(domain string, subdomains []string, cfg DNSConfig, source string, method string, resolver *DNSResolver, collector *resultCollector) {
	// resolveDomains fans out DNS queries with rate limiting and a breaker for failures.
	recordTypes := normalizeRecordTypes(cfg.RecordTypes)
	limiter := newRateLimiter(cfg.RateLimit)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMS)*time.Millisecond)
	defer cancel()

	jobs := make(chan queryJob)
	results := make(chan struct{})
	concurrency := cfg.ActiveDiscovery.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	maxFailures := cfg.MaxConsecutiveFailures
	if maxFailures <= 0 {
		maxFailures = 20
	}
	var consecutive int64
	var breaker int32

	for i := 0; i < concurrency; i++ {
		go func() {
			for job := range jobs {
				if atomic.LoadInt32(&breaker) == 1 {
					continue
				}
				limiter.wait()
				success := handleQuery(ctx, resolver, job, collector)
				if !success {
					count := atomic.AddInt64(&consecutive, 1)
					if count >= int64(maxFailures) {
						atomic.StoreInt32(&breaker, 1)
					}
				} else {
					atomic.StoreInt64(&consecutive, 0)
				}
			}
			results <- struct{}{}
		}()
	}

	for _, subdomain := range subdomains {
		for _, recordType := range recordTypes {
			jobs <- queryJob{
				domain:          domain,
				subdomain:       subdomain,
				recordType:      recordType,
				source:          source,
				discoveryMethod: method,
			}
		}
	}
	close(jobs)
	for i := 0; i < concurrency; i++ {
		<-results
	}
}

func handleQuery(ctx context.Context, resolver *DNSResolver, job queryJob, collector *resultCollector) bool {
	// handleQuery records both query telemetry and successful discoveries.
	qtype := dnsType(job.recordType)
	if qtype == 0 {
		return true
	}
	ts := now()
	answer, duration, err := queryWithRetry(ctx, resolver, job.subdomain, qtype)
	if err != nil {
		collector.addQuery(QueryEvent{
			Domain:          job.domain,
			Subdomain:       job.subdomain,
			RecordType:      job.recordType,
			Source:          job.source,
			DiscoveryMethod: job.discoveryMethod,
			Status:          "error",
			Error:           err.Error(),
			DurationMS:      duration.Milliseconds(),
			Timestamp:       ts,
		})
		collector.addError(ErrorEvent{
			Domain:          job.domain,
			Subdomain:       job.subdomain,
			RecordType:      job.recordType,
			Source:          job.source,
			DiscoveryMethod: job.discoveryMethod,
			Error:           err.Error(),
			Timestamp:       ts,
		})
		return false
	}

	status := "success"
	if answer.Rcode == dns.RcodeNameError {
		status = "nxdomain"
	}
	collector.addQuery(QueryEvent{
		Domain:          job.domain,
		Subdomain:       job.subdomain,
		RecordType:      job.recordType,
		Source:          job.source,
		DiscoveryMethod: job.discoveryMethod,
		Status:          status,
		Error:           "",
		DurationMS:      duration.Milliseconds(),
		Timestamp:       ts,
	})
	if len(answer.Values) == 0 {
		return true
	}
	collector.addDiscovery(Discovery{
		Domain:          job.domain,
		Subdomain:       job.subdomain,
		RecordType:      strings.ToUpper(job.recordType),
		Values:          dedupeStrings(answer.Values),
		Source:          job.source,
		DiscoveryMethod: job.discoveryMethod,
		FirstSeen:       ts,
		Timestamp:       ts,
	})
	return true
}

func bruteForceCandidates(domain string, words []string, maxDepth int) []string {
	// bruteForceCandidates builds candidate names while respecting depth limits.
	seen := map[string]bool{}
	var out []string
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		candidate := strings.ToLower(fmt.Sprintf("%s.%s", word, domain))
		if !withinDepth(domain, candidate, maxDepth) {
			continue
		}
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}

func filterByDepth(domain string, subdomains []string, maxDepth int) []string {
	// filterByDepth drops entries beyond the configured subdomain depth.
	seen := map[string]bool{}
	var out []string
	for _, subdomain := range subdomains {
		if !withinDepth(domain, subdomain, maxDepth) {
			continue
		}
		value := strings.ToLower(strings.TrimSuffix(subdomain, "."))
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func withinDepth(domain string, subdomain string, maxDepth int) bool {
	// withinDepth compares labels to avoid unbounded enumeration.
	if maxDepth <= 0 {
		return true
	}
	domainParts := strings.Split(domain, ".")
	subParts := strings.Split(subdomain, ".")
	if len(subParts) < len(domainParts) {
		return false
	}
	depth := len(subParts) - len(domainParts)
	return depth <= maxDepth
}

func normalizeRecordTypes(types []string) []string {
	// normalizeRecordTypes dedupes and uppercases record types.
	if len(types) == 0 {
		return []string{"A", "AAAA", "CNAME"}
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range types {
		value := strings.ToUpper(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func dnsType(recordType string) uint16 {
	switch strings.ToUpper(recordType) {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "SRV":
		return dns.TypeSRV
	default:
		return 0
	}
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func detectWildcard(domain string, cfg DNSConfig, resolver *DNSResolver, collector *resultCollector) *WildcardEvent {
	// detectWildcard probes a random label to identify wildcard DNS behavior.
	label, err := randomLabel(6)
	if err != nil {
		return nil
	}
	target := fmt.Sprintf("%s.%s", label, domain)
	recordTypes := normalizeRecordTypes(cfg.RecordTypes)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMS)*time.Millisecond)
	defer cancel()
	for _, recordType := range recordTypes {
		qtype := dnsType(recordType)
		answer, duration, err := queryWithRetry(ctx, resolver, target, qtype)
		if err != nil {
			collector.addQuery(QueryEvent{
				Domain:          domain,
				Subdomain:       target,
				RecordType:      recordType,
				Source:          "wildcard",
				DiscoveryMethod: "active",
				Status:          "error",
				Error:           err.Error(),
				DurationMS:      duration.Milliseconds(),
				Timestamp:       now(),
			})
			continue
		}
		collector.addQuery(QueryEvent{
			Domain:          domain,
			Subdomain:       target,
			RecordType:      recordType,
			Source:          "wildcard",
			DiscoveryMethod: "active",
			Status:          "success",
			Error:           "",
			DurationMS:      duration.Milliseconds(),
			Timestamp:       now(),
		})
		if len(answer.Values) > 0 {
			return &WildcardEvent{
				Domain:     domain,
				RecordType: recordType,
				Values:     dedupeStrings(answer.Values),
				Source:     "wildcard",
				Timestamp:  now(),
			}
		}
	}
	return nil
}

func randomLabel(size int) (string, error) {
	// randomLabel generates an unpredictable subdomain for wildcard checks.
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func attemptZoneTransferRecords(domain string, resolver *DNSResolver, timeout time.Duration) ([]axfrRecord, error) {
	// attemptZoneTransferRecords probes AXFR against discovered nameservers.
	var nameservers []string
	seen := map[string]bool{}
	for _, server := range resolver.servers {
		if server == "" {
			continue
		}
		if seen[server] {
			continue
		}
		seen[server] = true
		nameservers = append(nameservers, server)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	response, _, err := resolver.client.Exchange(msg, resolver.servers[0])
	if err == nil && response != nil {
		for _, answer := range response.Answer {
			if ns, ok := answer.(*dns.NS); ok {
				value := strings.TrimSuffix(ns.Ns, ".")
				if value == "" {
					continue
				}
				if seen[value] {
					continue
				}
				seen[value] = true
				nameservers = append(nameservers, value)
			}
		}
	}
	var records []axfrRecord
	for _, ns := range nameservers {
		transfer := new(dns.Transfer)
		transfer.DialTimeout = timeout
		transfer.ReadTimeout = timeout
		transfer.WriteTimeout = timeout
		axfr := new(dns.Msg)
		axfr.SetAxfr(dns.Fqdn(domain))
		channel, err := transfer.In(axfr, netJoinHostPort(ns))
		if err != nil {
			continue
		}
		for envelope := range channel {
			if envelope.Error != nil {
				continue
			}
			for _, record := range envelope.RR {
				rec := axfrRecordFromRR(record)
				if rec.name == "" || rec.rtype == "" {
					continue
				}
				if strings.HasSuffix(rec.name, domain) {
					records = append(records, rec)
				}
			}
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("zone transfer failed")
	}
	return records, nil
}

func axfrRecordFromRR(record dns.RR) axfrRecord {
	// axfrRecordFromRR normalizes DNS RR data into a compact record.
	name := strings.TrimSuffix(record.Header().Name, ".")
	switch rr := record.(type) {
	case *dns.A:
		return axfrRecord{name: name, rtype: "A", values: []string{rr.A.String()}}
	case *dns.AAAA:
		return axfrRecord{name: name, rtype: "AAAA", values: []string{rr.AAAA.String()}}
	case *dns.CNAME:
		return axfrRecord{name: name, rtype: "CNAME", values: []string{strings.TrimSuffix(rr.Target, ".")}}
	case *dns.MX:
		value := fmt.Sprintf("%d %s", rr.Preference, strings.TrimSuffix(rr.Mx, "."))
		return axfrRecord{name: name, rtype: "MX", values: []string{value}}
	case *dns.TXT:
		return axfrRecord{name: name, rtype: "TXT", values: []string{strings.Join(rr.Txt, " ")}}
	case *dns.SRV:
		value := fmt.Sprintf("%d %d %d %s", rr.Priority, rr.Weight, rr.Port, strings.TrimSuffix(rr.Target, "."))
		return axfrRecord{name: name, rtype: "SRV", values: []string{value}}
	case *dns.NS:
		return axfrRecord{name: name, rtype: "NS", values: []string{strings.TrimSuffix(rr.Ns, ".")}}
	case *dns.SOA:
		value := fmt.Sprintf("%s %s", strings.TrimSuffix(rr.Ns, "."), strings.TrimSuffix(rr.Mbox, "."))
		return axfrRecord{name: name, rtype: "SOA", values: []string{value}}
	default:
		return axfrRecord{}
	}
}

func netJoinHostPort(host string) string {
	// netJoinHostPort ensures a host is formatted with a DNS port.
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ":53"
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.JoinHostPort(strings.Trim(host, "[]"), "53")
	}
	if strings.Count(host, ":") > 1 {
		return net.JoinHostPort(host, "53")
	}
	return net.JoinHostPort(host, "53")
}

type rateLimiter struct {
	ch <-chan time.Time
}

func newRateLimiter(rps int) *rateLimiter {
	// newRateLimiter spaces DNS queries to respect rate limits.
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
