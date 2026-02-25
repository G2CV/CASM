from brain.adapters.publisher_multi import MultiPublisher


class RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, run_summary: dict) -> None:
        self.events.append(run_summary)


class FailingPublisher:
    def publish(self, run_summary: dict) -> None:
        raise RuntimeError("boom")


def test_multi_publisher_continues_after_failure() -> None:
    left = RecordingPublisher()
    right = RecordingPublisher()
    publisher = MultiPublisher([left, FailingPublisher(), right])

    payload = {"event_type": "run_summary", "run_id": "run-1"}
    publisher.publish(payload)

    assert left.events == [payload]
    assert right.events == [payload]


def test_multi_publisher_empty_list_is_noop() -> None:
    publisher = MultiPublisher()
    publisher.publish({"event_type": "run_summary", "run_id": "run-1"})
