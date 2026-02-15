from brain.core.dns_enum import build_dns_events, build_dns_sarif, filter_domains
from brain.core.scope import Scope, ScopeGuard


def test_filter_domains_respects_scope() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[53],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
        excluded_domains=["internal.example.com"],
    )
    guard = ScopeGuard(scope)
    allowed, blocked = filter_domains(["example.com", "internal.example.com"], guard)
    assert allowed == ["example.com"]
    assert blocked[0][0] == "internal.example.com"


def test_build_dns_events_includes_target_id_and_fingerprint() -> None:
    events = build_dns_events(
        engagement_id="eng",
        run_id="run-1",
        tool_version="dev",
        discoveries=[
            {
                "domain": "example.com",
                "subdomain": "api.example.com",
                "record_type": "A",
                "values": ["192.0.2.1"],
                "source": "crt.sh",
                "discovery_method": "passive",
                "timestamp": "2026-02-04T12:00:00Z",
            }
        ],
        queries=[],
        errors=[],
        wildcards=[],
        blocked_domains=[],
    )
    assert events[0]["type"] == "dns_discovery"
    assert events[0]["target_id"]
    assert events[0]["data"]["finding_fingerprint"]


def test_build_dns_sarif_emits_discovery() -> None:
    sarif = build_dns_sarif(
        engagement_id="eng",
        run_id="run-1",
        tool_version="dev",
        discoveries=[
            {
                "domain": "example.com",
                "subdomain": "api.example.com",
                "record_type": "A",
                "values": ["192.0.2.1"],
                "source": "crt.sh",
                "timestamp": "2026-02-04T12:00:00Z",
            }
        ],
        wildcards=[],
    )
    runs = sarif.get("runs", [])
    assert runs
    results = runs[0].get("results", [])
    assert results
    assert results[0]["ruleId"] == "DNS_SUBDOMAIN_DISCOVERED"
