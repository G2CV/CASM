from brain.core.redaction import redact_data, redact_text


def test_redact_authorization_bearer() -> None:
    text = "Authorization: Bearer secret-token-123"
    assert "[REDACTED]" in redact_text(text)


def test_redact_api_key_field() -> None:
    text = "api_key=abcd1234"
    assert redact_text(text) == "api_key= [REDACTED]"


def test_redact_nested_data() -> None:
    data = {"error": "token=xyz", "nested": ["x-api-key: abc"]}
    redacted = redact_data(data)
    assert redacted["error"] == "token= [REDACTED]"
    assert redacted["nested"][0] == "x-api-key: [REDACTED]"
