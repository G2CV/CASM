from __future__ import annotations

import logging

from brain.adapters.publisher_file import FilePublisher
from brain.adapters.publisher_multi import MultiPublisher
from brain.adapters.publisher_noop import NoopPublisher
from brain.adapters.publisher_webhook import WebhookPublisher
from brain.ports.publisher import Publisher


logger = logging.getLogger(__name__)


def resolve_publisher(notifications: dict | None) -> Publisher:
    if not isinstance(notifications, dict):
        return NoopPublisher()

    raw_publishers = notifications.get("publishers")
    if raw_publishers is None:
        return NoopPublisher()
    if not isinstance(raw_publishers, list):
        logger.warning("Invalid notifications.publishers configuration; expected a list")
        return NoopPublisher()

    builders = {
        "webhook": _build_webhook,
        "file": _build_file,
    }
    built: list[Publisher] = []
    for index, config in enumerate(raw_publishers):
        if not isinstance(config, dict):
            logger.warning("Skipping notifications publisher at index=%s: expected object", index)
            continue
        publisher_type = config.get("type")
        if not isinstance(publisher_type, str):
            logger.warning("Skipping notifications publisher at index=%s: missing type", index)
            continue
        builder = builders.get(publisher_type)
        if builder is None:
            logger.warning("Skipping notifications publisher at index=%s: unknown type=%s", index, publisher_type)
            continue
        publisher = builder(config)
        if publisher is not None:
            built.append(publisher)

    if not built:
        return NoopPublisher()
    if len(built) == 1:
        return built[0]
    return MultiPublisher(publishers=built)


def _build_webhook(config: dict) -> Publisher | None:
    url = config.get("url")
    if not isinstance(url, str) or not url.strip():
        logger.warning("Skipping webhook publisher: missing url")
        return None
    headers = config.get("headers")
    if headers is None:
        parsed_headers: dict[str, str] = {}
    elif isinstance(headers, dict):
        parsed_headers = {str(key): str(value) for key, value in headers.items()}
    else:
        logger.warning("Skipping webhook publisher: headers must be an object")
        return None
    try:
        timeout_seconds = int(config.get("timeout_seconds", 10))
        max_retries = int(config.get("max_retries", 2))
    except (TypeError, ValueError):
        logger.warning("Skipping webhook publisher: timeout_seconds/max_retries must be integers")
        return None
    return WebhookPublisher(
        url=url,
        timeout_seconds=timeout_seconds,
        headers=parsed_headers,
        max_retries=max_retries,
    )


def _build_file(config: dict) -> Publisher | None:
    path = config.get("path")
    if not isinstance(path, str) or not path.strip():
        logger.warning("Skipping file publisher: missing path")
        return None
    return FilePublisher(path=path)
