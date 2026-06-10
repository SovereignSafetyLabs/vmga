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


def validate_broker_proposal_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the broker-facing proposal request shape."""
    if not isinstance(payload, Mapping):
        raise ValueError("broker proposal payload must be an object")
    unknown = sorted(set(payload) - BROKER_PROPOSAL_FIELDS)
    if unknown:
        raise ValueError(f"unknown broker proposal field(s): {', '.join(unknown)}")
    if not payload.get("action") or not payload.get("actor_id"):
        raise ValueError("action and actor_id are required")
    return dict(payload)
