"""Small standalone governance model types used by VMGA.

The original VMGA reference lived inside the Vesta governance repository and
imported these shapes from ``core.models``. Keeping the minimal contract local
lets VMGA run as its own package while fuller host integrations can translate
to their native governance envelopes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ExecutionRequestEnvelope:
    session_id: str
    actor_id: str
    tool_id: str
    plugin_id: str
    tool_input: Dict[str, Any]
    request_id: str = field(default_factory=lambda: str(uuid4()))
    requested_at_utc: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "0.1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "tool_id": self.tool_id,
            "plugin_id": self.plugin_id,
            "requested_at_utc": self.requested_at_utc,
            "tool_input": self.tool_input,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ExecutionResultEnvelope:
    request_id: str
    session_id: str
    status: str
    finished_at_utc: str
    duration_ms: int
    tool_output: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "0.1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "status": self.status,
            "finished_at_utc": self.finished_at_utc,
            "duration_ms": self.duration_ms,
            "tool_output": self.tool_output,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    rule_id: Optional[str] = None
    error_code: Optional[str] = None
