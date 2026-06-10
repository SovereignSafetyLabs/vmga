"""Redaction helpers for shareable VMGA operator evidence."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping


SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "azure_key": re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_secret": re.compile(r"\bsk-(?:live|test)-[A-Za-z0-9]{16,}\b"),
    "google_oauth_token": re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----"),
}


def redact_text(text: str, extra_values: Iterable[str] | None = None) -> str:
    """Redact known secret patterns and caller-supplied sensitive values."""
    redacted = text
    for pattern in SECRET_PATTERNS.values():
        redacted = pattern.sub("[REDACTED]", redacted)
    for value in extra_values or []:
        if value:
            redacted = redacted.replace(str(value), "[REDACTED]")
    return redacted


def redact_json(value: Any, extra_values: Iterable[str] | None = None) -> Any:
    """Redact a JSON-compatible structure without changing its shape."""
    if isinstance(value, str):
        return redact_text(value, extra_values)
    if isinstance(value, list):
        return [redact_json(item, extra_values) for item in value]
    if isinstance(value, tuple):
        return [redact_json(item, extra_values) for item in value]
    if isinstance(value, Mapping):
        return {str(key): redact_json(item, extra_values) for key, item in value.items()}
    return value


def dumps_redacted(value: Any, extra_values: Iterable[str] | None = None) -> str:
    """JSON dump a redacted structure with stable ordering."""
    return json.dumps(redact_json(value, extra_values), sort_keys=True)
