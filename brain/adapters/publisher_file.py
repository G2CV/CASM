from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class FilePublisher:
    path: str

    def publish(self, run_summary: dict) -> None:
        try:
            destination = Path(self.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(run_summary, sort_keys=True) + "\n")
        except (OSError, TypeError, ValueError) as exc:
            logger.warning(
                "File publish failed path=%s error_type=%s",
                self.path,
                type(exc).__name__,
            )
