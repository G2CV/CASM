from __future__ import annotations

import logging
from dataclasses import dataclass, field

from brain.ports.publisher import Publisher


logger = logging.getLogger(__name__)


@dataclass
class MultiPublisher:
    publishers: list[Publisher] = field(default_factory=list)

    def publish(self, run_summary: dict) -> None:
        for publisher in self.publishers:
            try:
                publisher.publish(run_summary)
            except Exception as exc:  # defensive boundary for custom publishers
                logger.warning(
                    "Publisher dispatch failed publisher=%s error_type=%s",
                    publisher.__class__.__name__,
                    type(exc).__name__,
                )
