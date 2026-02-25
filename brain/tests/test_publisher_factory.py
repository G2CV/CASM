from brain.adapters.publisher_factory import resolve_publisher
from brain.adapters.publisher_file import FilePublisher
from brain.adapters.publisher_multi import MultiPublisher
from brain.adapters.publisher_noop import NoopPublisher
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
