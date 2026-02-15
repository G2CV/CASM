
from __future__ import annotations

import json
from dataclasses import dataclass
import socket
from typing import cast
from pathlib import Path
from urllib.parse import urlparse

from brain.core.scope import Scope, ScopeGuard


@dataclass
class TargetRecord:
    target: str
    protocol: str
    host: str
    port: int
    resolved_ip: str | None
    allowed: bool
    reason: str | None
    source: str
    source_path: str | None = None


def build_probe_inventory(scope: Scope) -> list[TargetRecord]:
    guard = ScopeGuard(scope)
    records: list[TargetRecord] = []
    for host in scope.seed_targets:
        resolved_ip = _resolve_ip(host, scope.inventory_resolve_ips)
        for port in scope.allowed_ports:
            decision = guard.check_target(host, port, "tcp")
            records.append(
                TargetRecord(
                    target=f"{host}:{port}",
                    protocol="tcp",
                    host=host,
                    port=port,
                    resolved_ip=resolved_ip,
                    allowed=decision.allowed,
                    reason=decision.reason,
                    source="seed",
                    source_path=None,
                )
            )
    return _sorted(records)


def build_http_verify_inventory(scope: Scope, urls: list[str], https_ports: list[int]) -> list[TargetRecord]:
    guard = ScopeGuard(scope)
    records: list[TargetRecord] = []
    for url in urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        protocol = parsed.scheme
        if port in https_ports:
            protocol = "https"
            url = f"https://{host}:{port}{parsed.path or '/'}"
        decision = guard.check_target(host, port, protocol)
        resolved_ip = _resolve_ip(host, scope.inventory_resolve_ips)
        records.append(
            TargetRecord(
                target=url,
                protocol=protocol,
                host=host,
                port=port,
                resolved_ip=resolved_ip,
                allowed=decision.allowed,
                reason=decision.reason,
                source="derived_http",
                source_path=None,
            )
        )
    return _sorted(records)


def write_inventory(path: str, records: list[TargetRecord]) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.__dict__, sort_keys=True) + "\n")
    return str(out)


def _sorted(records: list[TargetRecord]) -> list[TargetRecord]:
    return sorted(records, key=lambda item: (item.protocol, item.host, item.port, item.target))


def _resolve_ip(host: str, enabled: bool) -> str | None:
    if not host:
        return None
    if _is_ip(host):
        return host
    if not enabled:
        return None
    try:
        info = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    for family, _, _, _, sockaddr in info:
        if family == socket.AF_INET:
            return cast(str, sockaddr[0])
        if family == socket.AF_INET6:
            return cast(str, sockaddr[0])
    return None


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False
