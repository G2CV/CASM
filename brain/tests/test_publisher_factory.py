from brain.adapters.publisher_factory import resolve_publisher
from brain.adapters.publisher_file import FilePublisher
from brain.adapters.publisher_multi import MultiPublisher
from brain.adapters.publisher_noop import NoopPublisher
from brain.adapters.publisher_routing import RoutingPublisher
from brain.adapters.publisher_webhook import WebhookPublisher


def test_resolve_publisher_none_returns_noop() -> None:
    publisher = resolve_publisher(None)
    assert isinstance(publisher, NoopPublisher)


def test_resolve_publisher_single_webhook_returns_webhook() -> None:
    publisher = resolve_publisher(
        {
            "publishers": [
                {
                    "type": "webhook",
                    "url": "https://example.com/hook",
                }
            ]
        }
    )
    assert isinstance(publisher, WebhookPublisher)


def test_resolve_publisher_multiple_returns_multi() -> None:
    publisher = resolve_publisher(
        {
            "publishers": [
                {"type": "webhook", "url": "https://example.com/hook"},
                {"type": "file", "path": "runs/notifications.jsonl"},
            ]
        }
    )
    assert isinstance(publisher, MultiPublisher)
    assert len(publisher.publishers) == 2


def test_resolve_publisher_unknown_or_invalid_are_skipped() -> None:
    publisher = resolve_publisher(
        {
            "publishers": [
                {"type": "unknown"},
                {"type": "file"},
                "not-a-dict",
                {"type": "webhook", "url": "https://example.com/hook"},
            ]
        }
    )
    assert isinstance(publisher, WebhookPublisher)


def test_resolve_publisher_file_only() -> None:
    publisher = resolve_publisher(
        {
            "publishers": [
                {"type": "file", "path": "runs/notifications.jsonl"},
            ]
        }
    )
    assert isinstance(publisher, FilePublisher)


def test_resolve_publisher_route_filters_event_and_severity(tmp_path) -> None:
    event_path = tmp_path / "notifications.jsonl"
    publisher = resolve_publisher(
        {
            "routes": [
                {
                    "name": "security",
                    "events": ["finding_added"],
                    "min_severity": "medium",
                    "publisher": {"type": "file", "path": str(event_path)},
                }
            ]
        }
    )

    assert isinstance(publisher, RoutingPublisher)

    publisher.publish({"event_type": "finding_added", "severity": "low"})
    publisher.publish({"event_type": "run_summary", "severity": "critical"})
    assert not event_path.exists()

    publisher.publish(
        {
            "event_type": "finding_added",
            "severity": "high",
            "rule_id": "MISSING_CSP",
            "uri": "https://example.com/",
        }
    )

    lines = event_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert '"notification_route": "security"' in lines[0]


def test_resolve_publisher_route_supports_webhook_template() -> None:
    publisher = resolve_publisher(
        {
            "routes": [
                {
                    "name": "slack",
                    "events": ["finding_added"],
                    "publisher": {
                        "type": "webhook",
                        "url": "https://example.com/hook",
                        "template": "slack",
                    },
                }
            ]
        }
    )

    assert isinstance(publisher, RoutingPublisher)
    assert isinstance(publisher.publisher, WebhookPublisher)
    assert publisher.publisher.template is not None
    payload = publisher.publisher.template({"event_type": "finding_added", "severity": "high"})
    assert payload["text"].startswith("Finding Added")
