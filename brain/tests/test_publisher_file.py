import json

from brain.adapters.publisher_file import FilePublisher


def test_file_publisher_appends_jsonl_and_creates_parent(tmp_path) -> None:
    output = tmp_path / "nested" / "notifications.jsonl"
    publisher = FilePublisher(path=str(output))

    publisher.publish({"event_type": "run_summary", "run_id": "run-1"})
    publisher.publish({"event_type": "run_summary", "run_id": "run-2"})

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["run_id"] == "run-1"
    assert json.loads(lines[1])["run_id"] == "run-2"


def test_file_publisher_handles_invalid_path(tmp_path) -> None:
    directory_path = tmp_path / "directory"
    directory_path.mkdir()
    publisher = FilePublisher(path=str(directory_path))

    publisher.publish({"event_type": "run_summary", "run_id": "run-1"})
