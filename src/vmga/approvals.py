"""Approval contract helpers for VMGA."""

from __future__ import annotations

from typing import Any, Dict

from .vmga_adapter import ApprovalRecord

APPROVAL_SCHEMA_VERSION = "0.1"


def approval_contract(approval: ApprovalRecord) -> Dict[str, Any]:
    data = approval.to_dict()
    data["schema_version"] = APPROVAL_SCHEMA_VERSION
    return data


def validate_approval_dict(data: Dict[str, Any]) -> ApprovalRecord:
    if not isinstance(data, dict):
        raise ValueError("VMGA approval must be an object")
    required = {"proposal_id", "proposal_hash", "approver_id", "approved_at", "expires_at"}
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"Missing VMGA approval field(s): {', '.join(missing)}")
    return ApprovalRecord.from_dict(data)
