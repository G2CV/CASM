from __future__ import annotations

import logging

from brain.adapters.publisher_file import FilePublisher
from brain.adapters.publisher_multi import MultiPublisher
from brain.adapters.publisher_noop import NoopPublisher
from brain.adapters.publisher_routing import RouteFilter, RoutingPublisher
from brain.adapters.publisher_webhook import WebhookPublisher, resolve_webhook_template
from brain.ports.publisher import Publisher


logger = logging.getLogger(__name__)


def resolve_publisher(notifications: dict | None) -> Publisher:
    if not isinstance(notifications, dict):
        return NoopPublisher()

    built: list[Publisher] = []

    raw_publishers = notifications.get("publishers")
    if raw_publishers is not None and not isinstance(raw_publishers, list):
        logger.warning("Invalid notifications.publishers configuration; expected a list")
    elif isinstance(raw_publishers, list):
        built.extend(_build_publishers(raw_publishers))

    raw_routes = notifications.get("routes")
    if raw_routes is not None and not isinstance(raw_routes, list):
        logger.warning("Invalid notifications.routes configuration; expected a list")
    elif isinstance(raw_routes, list):
        built.extend(_build_routes(raw_routes))

    if not built:
        return NoopPublisher()
    if len(built) == 1:
        return built[0]
    return MultiPublisher(publishers=built)


def _build_publishers(raw_publishers: list) -> list[Publisher]:
    built: list[Publisher] = []
    for index, config in enumerate(raw_publishers):
        publisher = _build_publisher(config, context=f"notifications publisher at index={index}")
        if publisher is not None:
            built.append(publisher)
    return built


def _build_publisher(config: object, context: str) -> Publisher | None:
    builders = {
        "webhook": _build_webhook,
        "file": _build_file,
    }
    if not isinstance(config, dict):
        logger.warning("Skipping %s: expected object", context)
        return None
    publisher_type = config.get("type")
    if not isinstance(publisher_type, str):
        logger.warning("Skipping %s: missing type", context)
        return None
    builder = builders.get(publisher_type)
    if builder is None:
        logger.warning("Skipping %s: unknown type=%s", context, publisher_type)
        return None
    return builder(config)


def _build_routes(raw_routes: list) -> list[Publisher]:
    routes: list[Publisher] = []
    for index, config in enumerate(raw_routes):
        if not isinstance(config, dict):
            logger.warning("Skipping notifications route at index=%s: expected object", index)
            continue

        name = str(config.get("name") or f"route-{index}")
        publisher_config = config.get("publisher")
        if publisher_config is None and isinstance(config.get("type"), str):
            publisher_config = config

        publisher = _build_publisher(
            publisher_config,
            context=f"notifications route name={name} publisher",
        )
        if publisher is None:
            continue

        routes.append(
            RoutingPublisher(
                name=name,
                route_filter=RouteFilter(
                    events=_string_list(config.get("events") or config.get("event_types")),
                    min_severity=_optional_string(config.get("min_severity")),
                    rule_ids=_string_list(config.get("rule_ids") or config.get("rule_id")),
                    uri_regex=_optional_string(config.get("uri_regex")),
                ),
                publisher=publisher,
            )
        )
    return routes


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
    try:
        template = resolve_webhook_template(_optional_string(config.get("template")))
    except ValueError as exc:
        logger.warning("Skipping webhook publisher: %s", exc)
        return None
    return WebhookPublisher(
        url=url,
        timeout_seconds=timeout_seconds,
        headers=parsed_headers,
        max_retries=max_retries,
        template=template,
    )


def _build_file(config: dict) -> Publisher | None:
    path = config.get("path")
    if not isinstance(path, str) or not path.strip():
        logger.warning("Skipping file publisher: missing path")
        return None
    return FilePublisher(path=path)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []
