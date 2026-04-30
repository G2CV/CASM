from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


logger = logging.getLogger(__name__)


def resolve_webhook_template(name: str | None) -> Callable[[dict], dict] | None:
    if name is None or not str(name).strip() or str(name).strip().lower() in {"raw", "generic"}:
        return None
    templates = {
        "slack": _slack_payload,
        "teams": _teams_payload,
        "discord": _discord_payload,
    }
    template = templates.get(str(name).strip().lower())
    if template is None:
        raise ValueError(f"Unsupported webhook template: {name}")
    return template


@dataclass
class WebhookPublisher:
    url: str
    timeout_seconds: int = 10
    headers: dict[str, str] = field(default_factory=dict)
    max_retries: int = 2
    template: Callable[[dict], dict] | None = None

    def publish(self, run_summary: dict) -> None:
        payload = run_summary if self.template is None else self.template(run_summary)
        attempts = 1 + max(0, int(self.max_retries))
        request_headers = {"Content-Type": "application/json", **self.headers}

        for attempt in range(1, attempts + 1):
            try:
                body = json.dumps(payload, sort_keys=True).encode("utf-8")
                request = urllib.request.Request(
                    self.url,
                    data=body,
                    headers=request_headers,
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=self.timeout_seconds):
                    return
            except (urllib.error.URLError, OSError, TypeError, ValueError) as exc:
                if attempt >= attempts:
                    logger.warning(
                        "Webhook publish failed url=%s attempts=%s error_type=%s",
                        self.url,
                        attempts,
                        type(exc).__name__,
                    )
                    return
                logger.warning(
                    "Webhook publish retrying url=%s attempt=%s/%s error_type=%s",
                    self.url,
                    attempt,
                    attempts,
                    type(exc).__name__,
                )
                time.sleep(attempt)


def _slack_payload(event: dict) -> dict:
    text = _summary_text(event)
    return {
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
        ],
    }


def _discord_payload(event: dict) -> dict:
    return {
        "content": _summary_text(event),
        "embeds": [
            {
                "title": _title(event),
                "description": _description(event),
                "color": _severity_color(event),
            }
        ],
    }


def _teams_payload(event: dict) -> dict:
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": _summary_text(event),
        "themeColor": f"{_severity_color(event):06X}",
        "title": _title(event),
        "text": _description(event),
    }


def _summary_text(event: dict) -> str:
    title = _title(event)
    description = _description(event)
    if not description:
        return title
    return f"{title}: {description}"


def _title(event: dict) -> str:
    event_type = str(event.get("event_type") or event.get("type") or "notification")
    severity = str(event.get("severity") or "").strip()
    rule_id = str(event.get("rule_id") or event.get("ruleId") or "").strip()
    parts = [event_type.replace("_", " ").title()]
    if severity:
        parts.append(severity.upper())
    if rule_id:
        parts.append(rule_id)
    return " | ".join(parts)


def _description(event: dict) -> str:
    message = str(event.get("message") or "").strip()
    uri = str(event.get("uri") or event.get("target") or "").strip()
    run_id = str(event.get("run_id") or "").strip()
    parts = []
    if message:
        parts.append(message)
    if uri:
        parts.append(f"Target: {uri}")
    if run_id:
        parts.append(f"Run: {run_id}")
    return "\n".join(parts)


def _severity_color(event: dict) -> int:
    severity = str(event.get("severity") or "info").lower()
    colors = {
        "critical": 0xB91C1C,
        "high": 0xDC2626,
        "medium": 0xD97706,
        "low": 0x2563EB,
        "info": 0x2563EB,
        "unknown": 0x64748B,
    }
    return colors.get(severity, colors["unknown"])
