from brain.core.inventory import build_http_verify_inventory, build_probe_inventory
from brain.core.scope import Scope


def test_probe_inventory_deterministic() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[443, 80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    records = build_probe_inventory(scope)
    assert [r.target for r in records] == ["example.com:80", "example.com:443"]
    assert all(record.resolved_ip is None for record in records)


def test_http_verify_inventory_deterministic() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[80, 443],
        allowed_protocols=["http", "https"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    records = build_http_verify_inventory(
        scope,
        ["https://example.com/", "http://example.com:80/"],
        [443, 8443, 8444],
    )
    assert [r.target for r in records] == ["http://example.com:80/", "https://example.com:443/"]
    assert all(record.resolved_ip is None for record in records)
