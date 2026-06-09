"""VMGA evidence event helpers and verifier."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

EVIDENCE_SCHEMA_VERSION = "0.1"

REQUIRED_SEQUENCE_FOR_EXECUTION = [
    "vmga_proposal_received",
    "vmga_proposal_approved",
    "vmga_action_executed",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_event(event_type: str, **payload: Any) -> Dict[str, Any]:
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "event_type": event_type,
        "timestamp": payload.pop("timestamp", utc_now_iso()),
        **payload,
    }


@dataclass
class EvidenceVerificationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "errors": self.errors, "warnings": self.warnings}


def load_jsonl_events(path: str | Path) -> List[Dict[str, Any]]:
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc
    return events


def verify_events(events: Iterable[Dict[str, Any]]) -> EvidenceVerificationResult:
    errors: List[str] = []
    by_proposal: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for event in events:
        if "event_type" not in event:
            errors.append("event missing event_type")
            continue
        by_proposal.setdefault(event.get("proposal_id"), []).append(event)

    for proposal_id, proposal_events in by_proposal.items():
        event_types = [event.get("event_type") for event in proposal_events]
        if "vmga_action_executed" in event_types:
            for required in REQUIRED_SEQUENCE_FOR_EXECUTION:
                if required not in event_types:
                    errors.append(f"{proposal_id}: missing {required} before execution")
            exec_index = event_types.index("vmga_action_executed")
            for required in REQUIRED_SEQUENCE_FOR_EXECUTION[:-1]:
                if required in event_types and event_types.index(required) > exec_index:
                    errors.append(f"{proposal_id}: {required} appears after execution")
        for event in proposal_events:
            if event.get("event_type") in {"vmga_proposal_received", "vmga_action_executed"}:
                if event.get("policy_state") in {"DENY", "LOCKDOWN"} and not (
                    event.get("error_code") or event.get("vesta_rule_id")
                ):
                    errors.append(f"{proposal_id}: denial event missing error_code/rule_id")
            if "approval_token" in event:
                errors.append(f"{proposal_id}: raw approval_token leaked in evidence")

    return EvidenceVerificationResult(valid=not errors, errors=errors)
