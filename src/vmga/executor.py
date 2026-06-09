"""VMGA execution helpers."""

from __future__ import annotations

from typing import Any, Dict

from .vmga_adapter import VMGAGmailAdapter


class VMGAExecutor:
    def __init__(self, adapter: VMGAGmailAdapter, backend: Any):
        self.adapter = adapter
        self.backend = backend

    def execute_approved(self, proposal_id: str, proposal_hash: str, approval_token: str) -> Dict[str, Any]:
        approval = self.adapter.approvals.get(proposal_id)
        action = approval.action if approval else "unknown"

        def handler(_request: Any) -> Dict[str, Any]:
            payload = {
                "proposal_id": proposal_id,
                "proposal_hash": proposal_hash,
            }
            return self.backend.execute(action, payload)

        return self.adapter.execute_approved(proposal_id, proposal_hash, approval_token, handler)
