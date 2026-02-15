
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from brain.core.scope import Scope


@dataclass
class HttpVerifyRequest:
    payload: dict
    evidence_path: str
    sarif_path: str


def build_http_targets(scope: Scope, seeds: list[str]) -> list[dict]:
    """Expand seed hosts/URLs into HTTP verification targets.

    Args:
        scope (Scope): Scope config used to determine allowed protocols/ports.
        seeds (list[str]): Hostnames/IPs or fully-qualified URLs.

    Returns:
        list[dict]: Targets with "url" and "method" keys for the http-verify tool.

    Notes:
        https_ports are forced to https:// regardless of the default protocol
        list so TLS probes are not accidentally downgraded.
    """
    targets: list[dict] = []
    allowed_protocols = [p for p in scope.allowed_protocols if p in {"http", "https"}]
    https_ports = scope.http_verify_https_ports
    for seed in seeds:
        if seed.startswith("http://") or seed.startswith("https://"):
            parsed = urlparse(seed)
            if parsed.scheme in allowed_protocols:
                targets.append({"url": seed, "method": "HEAD"})
            continue
        for port in scope.allowed_ports:
            if port in https_ports:
                url = f"https://{seed}:{port}/"
                targets.append({"url": url, "method": "HEAD"})
                continue
            for protocol in allowed_protocols:
                url = f"{protocol}://{seed}:{port}/"
                targets.append({"url": url, "method": "HEAD"})
    return targets


def build_http_verify_request(scope: Scope, run_id: str, dry_run: bool, run_dir: str) -> HttpVerifyRequest:
    """Build the tool payload plus artifact paths for http-verify.

    Args:
        scope (Scope): Current scope and policy controls for limits and TLS.
        run_id (str): Run identifier used to namespace artifacts.
        dry_run (bool): When True, tool should avoid network I/O.
        run_dir (str): Directory where evidence/SARIF artifacts are written.

    Returns:
        HttpVerifyRequest: Payload and output paths wired to the run directory.
    """
    https_ports = scope.http_verify_https_ports
    targets = build_http_targets(scope, scope.seed_targets)

    evidence_path = f"{run_dir}/evidence.jsonl"
    sarif_path = f"{run_dir}/results.sarif"

    payload = {
        "engagement_id": scope.engagement_id,
        "run_id": run_id,
        "dry_run": dry_run,
        "debug": False,
        "profile": scope.http_verify_profile,
        "https_ports": https_ports,
        "tls": {
            "ca_bundle_path": scope.http_verify_tls_ca_bundle_path or "",
            "insecure_skip_verify": scope.http_verify_tls_insecure_skip_verify,
            "server_name": scope.http_verify_tls_server_name or "",
        },
        "scope": {
            "allowed_domains": scope.allowed_domain_patterns(),
            "allowed_ips": scope.allowed_ips,
            "allowed_ports": scope.allowed_ports,
            "allowed_protocols": scope.allowed_protocols,
        },
        "targets": targets,
        "limits": {
            "max_concurrency": scope.max_concurrency,
            "rps": int(scope.max_rate),
            "timeout_ms": scope.per_attempt_timeout_ms,
            "max_redirects": scope.http_verify_max_redirects,
            "max_body_bytes": scope.http_verify_max_body_bytes,
            "tls_expiry_days": scope.http_verify_tls_expiry_days,
        },
        "evidence": {"jsonl_path": evidence_path},
        "sarif": {"enabled": True, "path": sarif_path},
    }

    return HttpVerifyRequest(payload=payload, evidence_path=evidence_path, sarif_path=sarif_path)
