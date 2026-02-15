
from __future__ import annotations

import re
from typing import Any


_PATTERNS = [
    (re.compile(r"(Authorization\s*:\s*Bearer\s+)[^\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(x-api-key\s*[:=])\s*[^\s]+", re.IGNORECASE), r"\1 [REDACTED]"),
    (re.compile(r"(api_key\s*[:=])\s*[^\s]+", re.IGNORECASE), r"\1 [REDACTED]"),
    (re.compile(r"(token\s*[:=])\s*[^\s]+", re.IGNORECASE), r"\1 [REDACTED]"),
    (re.compile(r"(secret\s*[:=])\s*[^\s]+", re.IGNORECASE), r"\1 [REDACTED]"),
]


def redact_text(value: str) -> str:
    """Redact common credential patterns from text.

    Notes:
        Redaction happens before persistence to reduce accidental secret
        disclosure in evidence and logs.
    """
    redacted = value
    for pattern, repl in _PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted


def redact_data(value: Any) -> Any:
    """Recursively redact credential patterns from structured data."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_data(val) for key, val in value.items()}
    return value
