
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml


@dataclass
class Scope:
    engagement_id: str
    allowed_domains: list[str]
    allowed_ips: list[str]
    allowed_ports: list[int]
    allowed_protocols: list[str]
    seed_targets: list[str]
    max_rate: float
    max_concurrency: int
    per_attempt_timeout_ms: int = 750
    tool_timeout_ms: int = 5000
    http_verify_profile: str = "baseline"
    http_verify_max_redirects: int = 5
    http_verify_max_body_bytes: int = 32768
    http_verify_tls_expiry_days: int = 30
    http_verify_tls_ca_bundle_path: str | None = None
    http_verify_tls_insecure_skip_verify: bool = False
    http_verify_tls_server_name: str | None = None
    http_verify_https_ports: list[int] = field(default_factory=lambda: [443])
    inventory_resolve_ips: bool = False
    run_dir: str | None = None
    active_allowed: bool = False
    auth_allowed: bool = False
    time_window: dict | None = None
    dns_enumeration: dict | None = None
    allowed_subdomains: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    pdf_branding: dict | None = None
    pdf_diff: dict | None = None

    @staticmethod
    def from_file(path: str) -> "Scope":
        ext = Path(path).suffix.lower()
        with open(path, "r", encoding="utf-8") as handle:
            if ext in {".yaml", ".yml"}:
                data = yaml.safe_load(handle)
            elif ext == ".json":
                data = json.load(handle)
            else:
                raise ValueError(f"Unsupported scope file extension: {ext}")

        return Scope(
            engagement_id=data["engagement_id"],
            allowed_domains=data.get("allowed_domains", []),
            allowed_subdomains=data.get("allowed_subdomains", []),
            excluded_domains=data.get("excluded_domains", []),
            allowed_ips=data.get("allowed_ips", []),
            allowed_ports=[int(p) for p in data.get("allowed_ports", [])],
            allowed_protocols=data.get("allowed_protocols", ["tcp"]),
            seed_targets=data.get("seed_targets", []),
            max_rate=float(data.get("max_rate", 1.0)),
            max_concurrency=int(data.get("max_concurrency", 1)),
            per_attempt_timeout_ms=int(data.get("per_attempt_timeout_ms", 750)),
            tool_timeout_ms=int(data.get("tool_timeout_ms", 5000)),
            http_verify_profile=str(data.get("http_verify_profile", "baseline")),
            http_verify_max_redirects=int(data.get("http_verify_max_redirects", 5)),
            http_verify_max_body_bytes=int(data.get("http_verify_max_body_bytes", 32768)),
            http_verify_tls_expiry_days=int(data.get("http_verify_tls_expiry_days", 30)),
            http_verify_tls_ca_bundle_path=data.get("http_verify_tls_ca_bundle_path"),
            http_verify_tls_insecure_skip_verify=bool(data.get("http_verify_tls_insecure_skip_verify", False)),
            http_verify_tls_server_name=data.get("http_verify_tls_server_name"),
            http_verify_https_ports=[int(p) for p in data.get("http_verify_https_ports", [443])],
            inventory_resolve_ips=bool(data.get("inventory_resolve_ips", False)),
            run_dir=data.get("run_dir"),
            active_allowed=bool(data.get("active_allowed", False)),
            auth_allowed=bool(data.get("auth_allowed", False)),
            time_window=data.get("time_window"),
            dns_enumeration=data.get("dns_enumeration"),
            pdf_branding=data.get("pdf_branding"),
            pdf_diff=data.get("pdf_diff"),
        )

    def snapshot(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "allowed_domains": self.allowed_domains,
            "allowed_subdomains": self.allowed_subdomains,
            "excluded_domains": self.excluded_domains,
            "allowed_ips": self.allowed_ips,
            "allowed_ports": self.allowed_ports,
            "allowed_protocols": self.allowed_protocols,
            "seed_targets": self.seed_targets,
            "max_rate": self.max_rate,
            "max_concurrency": self.max_concurrency,
            "per_attempt_timeout_ms": self.per_attempt_timeout_ms,
            "tool_timeout_ms": self.tool_timeout_ms,
            "http_verify_profile": self.http_verify_profile,
            "http_verify_max_redirects": self.http_verify_max_redirects,
            "http_verify_max_body_bytes": self.http_verify_max_body_bytes,
            "http_verify_tls_expiry_days": self.http_verify_tls_expiry_days,
            "http_verify_tls_ca_bundle_path": self.http_verify_tls_ca_bundle_path,
            "http_verify_tls_insecure_skip_verify": self.http_verify_tls_insecure_skip_verify,
            "http_verify_tls_server_name": self.http_verify_tls_server_name,
            "http_verify_https_ports": self.http_verify_https_ports,
            "inventory_resolve_ips": self.inventory_resolve_ips,
            "run_dir": self.run_dir,
            "active_allowed": self.active_allowed,
            "auth_allowed": self.auth_allowed,
            "time_window": self.time_window,
            "dns_enumeration": self.dns_enumeration,
            "pdf_branding": self.pdf_branding,
            "pdf_diff": self.pdf_diff,
        }

    def allowed_domain_patterns(self) -> list[str]:
        patterns = list(self.allowed_domains)
        for value in self.allowed_subdomains:
            if value not in patterns:
                patterns.append(value)
        return patterns


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str | None


class ScopeGuard:
    """Centralized scope enforcement to keep tools policy-compliant.

    This avoids duplicating policy checks across adapters and keeps decisions
    consistent for reporting and auditing.
    """
    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self._allowed_ip_nets = [ipaddress.ip_network(cidr) for cidr in scope.allowed_ips]

    def check_target(self, host: str, port: int, protocol: str) -> ScopeDecision:
        """Validate a host/port/protocol tuple against the scope policy.

        Args:
            host (str): Hostname or IP address.
            port (int): Target port.
            protocol (str): Protocol label (e.g., tcp, http, https).

        Returns:
            ScopeDecision: Allowed/blocked decision with reason.
        """
        if protocol not in self.scope.allowed_protocols:
            return ScopeDecision(False, "protocol_not_allowed")
        if port not in self.scope.allowed_ports:
            return ScopeDecision(False, "port_not_allowed")

        if self._is_ip(host):
            return self._check_ip(host)
        return self._check_domain(host)

    def check_domain(self, host: str) -> ScopeDecision:
        """Validate a hostname against explicit domain rules.

        Args:
            host (str): Hostname to evaluate.

        Returns:
            ScopeDecision: Allowed/blocked decision with reason.

        Notes:
            Excluded domains take precedence over allowed patterns.
        """
        if self._is_excluded_domain(host):
            return ScopeDecision(False, "domain_excluded")
        return self._check_domain(host)

    def check_rate(self, rps: float, concurrency: int) -> ScopeDecision:
        """Validate requested rates against engagement-level limits.

        Args:
            rps (float): Requested requests per second.
            concurrency (int): Requested concurrency level.

        Returns:
            ScopeDecision: Allowed/blocked decision with reason.
        """
        if rps > self.scope.max_rate:
            return ScopeDecision(False, "rate_limit_exceeded")
        if concurrency > self.scope.max_concurrency:
            return ScopeDecision(False, "concurrency_limit_exceeded")
        return ScopeDecision(True, None)

    def _check_ip(self, host: str) -> ScopeDecision:
        ip = ipaddress.ip_address(host)
        for net in self._allowed_ip_nets:
            if ip in net:
                return ScopeDecision(True, None)
        return ScopeDecision(False, "ip_out_of_scope")

    def _check_domain(self, host: str) -> ScopeDecision:
        if self._is_excluded_domain(host):
            return ScopeDecision(False, "domain_excluded")
        patterns = self.scope.allowed_domain_patterns()
        for pattern in patterns:
            if fnmatch(host, pattern):
                return ScopeDecision(True, None)
        return ScopeDecision(False, "domain_out_of_scope")

    def _is_excluded_domain(self, host: str) -> bool:
        for pattern in self.scope.excluded_domains:
            if fnmatch(host, pattern):
                return True
        return False

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True
