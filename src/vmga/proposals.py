"""Versioned VMGA proposal contract helpers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .vmga_adapter import GmailAction, VMGAProposal

PROPOSAL_SCHEMA_VERSION = "0.1"


REQUIRED_PROPOSAL_FIELDS = {
    "proposal_id",
    "action",
    "actor_id",
    "requested_at",
}


def normalize_string_list(values: Iterable[str] | None) -> List[str]:
    return sorted(str(value) for value in (values or []))


def validate_proposal_dict(data: Dict[str, Any]) -> VMGAProposal:
    """Validate and build a VMGAProposal from untrusted input."""
    if not isinstance(data, dict):
        raise ValueError("VMGA proposal must be an object")

    missing = sorted(REQUIRED_PROPOSAL_FIELDS - set(data))
    if missing:
        raise ValueError(f"Missing VMGA proposal field(s): {', '.join(missing)}")

    action = GmailAction.from_string(str(data["action"]))
    if action is None:
        raise ValueError(f"Unknown VMGA action: {data['action']}")

    proposal = VMGAProposal(
        proposal_id=str(data["proposal_id"]),
        action=action,
        actor_id=str(data["actor_id"]),
        thread_id=data.get("thread_id"),
        message_ids=normalize_string_list(data.get("message_ids")),
        content=data.get("content"),
        recipients=normalize_string_list(data.get("recipients")),
        attachment_ids=normalize_string_list(data.get("attachment_ids")),
        justification=str(data.get("justification", "")),
        requested_at=str(data["requested_at"]),
    )
    return proposal


def proposal_contract(proposal: VMGAProposal) -> Dict[str, Any]:
    """Return the stable public contract representation."""
    data = proposal.to_dict()
    data["schema_version"] = PROPOSAL_SCHEMA_VERSION
    data["proposal_hash"] = proposal.compute_hash()
    return data
