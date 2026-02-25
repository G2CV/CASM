import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from brain.adapters.publisher_webhook import WebhookPublisher


def _start_server(statuses: list[int]):
    state = {
        "statuses": list(statuses),
        "requests": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length)
            state["requests"].append(
                {
                    "path": self.path,
                    "headers": dict(self.headers.items()),
                    "body": json.loads(body.decode("utf-8")),
                }
            )
            code = state["statuses"].pop(0) if state["statuses"] else 200
            self.send_response(code)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


def test_webhook_publisher_posts_payload_headers_and_template() -> None:
    server, state = _start_server([200])
    url = f"http://127.0.0.1:{server.server_port}/notify"
    publisher = WebhookPublisher(
        url=url,
        headers={"X-Test": "1"},
        max_retries=0,
        template=lambda event: {"text": event["event_type"]},
    )

    try:
        publisher.publish({"event_type": "run_summary", "run_id": "run-1"})
    finally:
        server.shutdown()
        server.server_close()

    assert len(state["requests"]) == 1
    sent = state["requests"][0]
    assert sent["path"] == "/notify"
    assert sent["headers"]["X-Test"] == "1"
    assert sent["body"] == {"text": "run_summary"}


def test_webhook_publisher_retries_on_transient_failure(monkeypatch) -> None:
    sleep_calls: list[int] = []
    monkeypatch.setattr("brain.adapters.publisher_webhook.time.sleep", lambda seconds: sleep_calls.append(seconds))

    server, state = _start_server([500, 200])
    url = f"http://127.0.0.1:{server.server_port}/notify"
    publisher = WebhookPublisher(url=url, max_retries=2)

    try:
        publisher.publish({"event_type": "run_summary", "run_id": "run-1"})
    finally:
        server.shutdown()
        server.server_close()

    assert len(state["requests"]) == 2
    assert sleep_calls == [1]


def test_webhook_publisher_handles_connection_failure() -> None:
    publisher = WebhookPublisher(
        url="http://127.0.0.1:1/notify",
        timeout_seconds=1,
        max_retries=0,
    )

    publisher.publish({"event_type": "run_summary", "run_id": "run-1"})
