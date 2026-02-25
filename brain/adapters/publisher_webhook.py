from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


logger = logging.getLogger(__name__)


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
