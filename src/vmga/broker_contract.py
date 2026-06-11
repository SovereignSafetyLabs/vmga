"""Broker request contract helpers."""

from __future__ import annotations

from typing import Any, Mapping

MAX_CONTENT_CHARS = 200_000
MAX_SCALAR_CHARS = 4_096
MAX_LIST_ITEMS = 100
MAX_RESULTS_LIMIT = 100
CONTROL_CHARS = ("\r", "\n", "\x00")

BROKER_PROPOSAL_FIELDS = {
    "action",
    "actor_id",
    "thread_id",
    "message_ids",
    "content",
    "recipients",
    "attachment_ids",
    "parameters",
    "justification",
    "sender",
    "subject",
    "search_query",
    "message_id",
    "max_results",
    "metadata",
    "cc",
    "bcc",
    "reply_to_message_id",
    "reply_to",
    "requested_at",
    "session_id",
    "correlation_id",
}

COMMON_PARAMETER_FIELDS = {
    "correlation_id",
    "metadata",
}

ACTION_PARAMETER_FIELDS = {
    "read": {"search_query", "message_id", "max_results"},
    "summarize": {"message_id"},
    "classify": {"message_id"},
    "extract_entities": {"message_id"},
    "recommend_draft": {"message_id"},
    "create_draft": {"subject", "cc", "bcc", "reply_to_message_id", "reply_to"},
    "send": {"subject", "cc", "bcc", "reply_to_message_id", "reply_to"},
    "forward": {"subject", "cc", "bcc", "reply_to_message_id", "reply_to"},
    "archive": set(),
    "delete": set(),
    "apply_label": {"label"},
    "download_attachment": {"output_dir"},
    "mark_read": set(),
    "move": {"destination"},
}

SINGLE_LINE_TOP_LEVEL_FIELDS = {
    "action",
    "actor_id",
    "thread_id",
    "sender",
    "subject",
    "search_query",
    "message_id",
    "cc",
    "bcc",
    "reply_to_message_id",
    "reply_to",
    "requested_at",
    "session_id",
    "correlation_id",
}

SINGLE_LINE_LIST_FIELDS = {
    "message_ids",
    "recipients",
    "attachment_ids",
}

MULTILINE_TEXT_FIELDS = {
    "content",
    "justification",
}


def _has_control_chars(value: str) -> bool:
    return any(char in value for char in CONTROL_CHARS)


def _validate_single_line(field_name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, (str, int, float)):
        text = str(value)
        if len(text) > MAX_SCALAR_CHARS:
            raise ValueError(f"{field_name} exceeds maximum length")
        if _has_control_chars(text):
            raise ValueError(f"{field_name} contains disallowed control characters")
        return
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError(f"{field_name} exceeds maximum item count")
        for item in value:
            _validate_single_line(field_name, item)
        return
    raise ValueError(f"{field_name} must be a scalar or list of scalars")


def _validate_text_field(field_name: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if len(value) > MAX_CONTENT_CHARS:
        raise ValueError(f"{field_name} exceeds maximum length")


def _validate_max_results(value: Any) -> None:
    if value is None:
        return
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError("max_results must be an integer") from None
    if parsed < 1 or parsed > MAX_RESULTS_LIMIT:
        raise ValueError(f"max_results must be between 1 and {MAX_RESULTS_LIMIT}")


def _validate_parameters(action: str, parameters: Any) -> None:
    if parameters is None:
        return
    if not isinstance(parameters, Mapping):
        raise ValueError("parameters must be an object")
    action_key = str(action).lower()
    allowed = COMMON_PARAMETER_FIELDS | ACTION_PARAMETER_FIELDS.get(action_key, set())
    unknown = sorted(str(key) for key in set(parameters) - allowed)
    if unknown:
        raise ValueError(f"unknown broker parameter field(s) for {action_key}: {', '.join(unknown)}")
    for key, value in parameters.items():
        if key == "metadata":
            if not isinstance(value, Mapping):
                raise ValueError("parameters.metadata must be an object")
            continue
        if key == "max_results":
            _validate_max_results(value)
            continue
        _validate_single_line(f"parameters.{key}", value)


def _validate_payload_values(payload: Mapping[str, Any]) -> None:
    for field_name in SINGLE_LINE_TOP_LEVEL_FIELDS:
        if field_name in payload:
            _validate_single_line(field_name, payload[field_name])
    for field_name in SINGLE_LINE_LIST_FIELDS:
        if field_name in payload:
            _validate_single_line(field_name, payload[field_name])
    for field_name in MULTILINE_TEXT_FIELDS:
        if field_name in payload:
            _validate_text_field(field_name, payload[field_name])
    if "max_results" in payload:
        _validate_max_results(payload["max_results"])
    if payload.get("metadata") is not None and not isinstance(payload["metadata"], Mapping):
        raise ValueError("metadata must be an object")


def validate_broker_proposal_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the broker-facing proposal request shape."""
    if not isinstance(payload, Mapping):
        raise ValueError("broker proposal payload must be an object")
    unknown = sorted(set(payload) - BROKER_PROPOSAL_FIELDS)
    if unknown:
        raise ValueError(f"unknown broker proposal field(s): {', '.join(unknown)}")
    if not payload.get("action") or not payload.get("actor_id"):
        raise ValueError("action and actor_id are required")
    _validate_payload_values(payload)
    _validate_parameters(str(payload["action"]), payload.get("parameters"))
    return dict(payload)
