"""Broker request contract helpers."""

from __future__ import annotations

from typing import Any, Mapping


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


def validate_broker_proposal_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the broker-facing proposal request shape."""
    if not isinstance(payload, Mapping):
        raise ValueError("broker proposal payload must be an object")
    unknown = sorted(set(payload) - BROKER_PROPOSAL_FIELDS)
    if unknown:
        raise ValueError(f"unknown broker proposal field(s): {', '.join(unknown)}")
    if not payload.get("action") or not payload.get("actor_id"):
        raise ValueError("action and actor_id are required")
    _validate_parameters(str(payload["action"]), payload.get("parameters"))
    return dict(payload)
