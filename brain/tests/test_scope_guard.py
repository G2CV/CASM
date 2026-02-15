from brain.core.scope import Scope, ScopeGuard


def test_scope_guard_allows_domain_and_port() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    guard = ScopeGuard(scope)
    decision = guard.check_target("example.com", 80, "tcp")
    assert decision.allowed


def test_scope_guard_blocks_wrong_port() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    guard = ScopeGuard(scope)
    decision = guard.check_target("example.com", 443, "tcp")
    assert not decision.allowed
    assert decision.reason == "port_not_allowed"


def test_scope_guard_blocks_out_of_scope_domain() -> None:
    scope = Scope(
        engagement_id="eng",
        allowed_domains=["example.com"],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["tcp"],
        seed_targets=["example.com"],
        max_rate=1.0,
        max_concurrency=1,
    )
    guard = ScopeGuard(scope)
    decision = guard.check_target("other.com", 80, "tcp")
    assert not decision.allowed
    assert decision.reason == "domain_out_of_scope"
