from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from brain.ports.publisher import Publisher


logger = logging.getLogger(__name__)


SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


@dataclass
class RouteFilter:
    events: list[str] = field(default_factory=list)
    min_severity: str | None = None
    rule_ids: list[str] = field(default_factory=list)
    uri_regex: str | None = None

    def matches(self, event: dict) -> bool:
        event_type = str(event.get("event_type") or event.get("type") or "")
        if self.events and event_type not in self.events:
            return False

        severity = event.get("severity")
        if self.min_severity and severity is not None:
            threshold = SEVERITY_RANK.get(self.min_severity.lower(), SEVERITY_RANK["low"])
            rank = SEVERITY_RANK.get(str(severity).lower(), SEVERITY_RANK["unknown"])
            if rank > threshold:
                return False

        if self.rule_ids:
            rule_id = str(event.get("rule_id") or event.get("ruleId") or "")
            if rule_id not in self.rule_ids:
                return False

        if self.uri_regex:
            uri = str(event.get("uri") or event.get("target") or "")
            try:
                if not re.search(self.uri_regex, uri):
                    return False
            except re.error as exc:
                logger.warning("Skipping notification route with invalid uri_regex=%s error=%s", self.uri_regex, exc)
                return False

        return True


@dataclass
class RoutingPublisher:
    name: str
    route_filter: RouteFilter
    publisher: Publisher

    def publish(self, run_summary: dict) -> None:
        if not self.route_filter.matches(run_summary):
            return
        payload = dict(run_summary)
        payload.setdefault("notification_route", self.name)
        self.publisher.publish(payload)
