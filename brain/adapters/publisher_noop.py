
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NoopPublisher:
    def publish(self, run_summary: dict) -> None:
        """No-op publisher for local runs and tests."""
        return None
