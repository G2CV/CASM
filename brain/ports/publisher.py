
from __future__ import annotations

from typing import Protocol


class Publisher(Protocol):
    """Publishing boundary for run summaries."""
    def publish(self, run_summary: dict) -> None:
        """Publish a run summary for downstream systems.

        Args:
            run_summary (dict): Summary payload produced by orchestration.
        """
        ...
