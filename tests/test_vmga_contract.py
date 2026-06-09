import json
import tempfile
from pathlib import Path

import pytest

from vmga import (
    ApprovalRecord,
    FakeGmailBackend,
    GmailAction,
    SQLiteStateStore,
    VMGABroker,
    VMGAExecutor,
    VMGAGmailAdapter,
    VMGAProposal,
)
from vmga.approvals import approval_contract, validate_approval_dict
from vmga.evidence import evidence_event, verify_events
from vmga.ledger import JSONLVMGALedger, LedgerVestaAdapter
from vmga.proposals import proposal_contract, validate_proposal_dict


class MockLedger:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


class MockVesta:
    def __init__(self):
        self.audit_ledger = MockLedger()

    def execute(self, request, handler):
        output = handler(request)

        class Result:
            request_id = request.request_id
            duration_ms = 1
            tool_output = output

        return Result()


def make_adapter(state_store):
    return VMGAGmailAdapter(
        vesta_adapter=MockVesta(),
        profile="draft_assist",
        policy_rules={"allowed_actions": ["read", "create_draft"], "kinetic_requires_approval": True},
        state_store=state_store,
        approval_secret="test_secret",
    )


def test_versioned_proposal_contract_round_trip():
    proposal = VMGAProposal(
        proposal_id="prop_1",
        action=GmailAction.CREATE_DRAFT,
        actor_id="agent_1",
        recipients=["z@example.com", "a@example.com"],
        requested_at="2026-06-09T00:00:00+00:00",
    )
    contract = proposal_contract(proposal)
    assert contract["schema_version"] == "0.1"
    rebuilt = validate_proposal_dict(contract)
    assert rebuilt.compute_hash() == proposal.compute_hash()


def test_validate_proposal_rejects_missing_fields():
    with pytest.raises(ValueError, match="Missing VMGA proposal field"):
        validate_proposal_dict({"action": "read"})


def test_approval_contract_round_trip():
    approval = ApprovalRecord(
        proposal_id="prop_1",
        proposal_hash="sha256:" + "a" * 64,
        approver_id="operator_1",
        approved_at="2026-06-09T00:00:00+00:00",
        expires_at="2026-06-09T01:00:00+00:00",
    )
    contract = approval_contract(approval)
    assert contract["schema_version"] == "0.1"
    assert validate_approval_dict(contract).proposal_id == "prop_1"


def test_sqlite_state_persists_approval_used_flag():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        adapter = make_adapter(SQLiteStateStore(db_path))
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        assert adapter.approve_proposal(result["proposal_id"], "operator_1", token)["status"] == "APPROVED"
        exec_result = adapter.execute_approved(result["proposal_id"], result["proposal_hash"], token, lambda request: {"ok": True})
        assert exec_result["status"] == "SUCCESS"

        restarted = make_adapter(SQLiteStateStore(db_path))
        replay = restarted.execute_approved(result["proposal_id"], result["proposal_hash"], token, lambda request: {"ok": True})
        assert replay["status"] == "DENY"
        assert replay["error_code"] == "vmga_approval_already_used"


def test_fake_backend_records_executor_operation():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        backend = FakeGmailBackend()
        executor = VMGAExecutor(adapter, backend)
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        adapter.approve_proposal(result["proposal_id"], "operator_1", token)
        exec_result = executor.execute_approved(result["proposal_id"], result["proposal_hash"], token)
        assert exec_result["status"] == "SUCCESS"
        assert backend.operations[0]["action"] == "create_draft"


def test_broker_propose_and_execute_fail_closed_without_executor():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        broker = VMGABroker(adapter)
        assert broker.health()["status"] == "ok"
        bad = broker.propose({"action": "create_draft"})
        assert bad["status"] == "DENY"
        assert bad["error_code"] == "vmga_broker_bad_request"
        denied = broker.execute({"proposal_id": "p", "proposal_hash": "h", "approval_token": "t"})
        assert denied["error_code"] == "vmga_executor_unavailable"


def test_evidence_verifier_accepts_valid_sequence_and_rejects_token_leak():
    proposal_hash = "sha256:" + "a" * 64
    events = [
        evidence_event("vmga_proposal_received", proposal_id="p1", proposal_hash=proposal_hash, policy_state="REVIEW_REQUIRED"),
        evidence_event("vmga_proposal_approved", proposal_id="p1", proposal_hash=proposal_hash, approval_token_hash="abc"),
        evidence_event("vmga_action_executed", proposal_id="p1", proposal_hash=proposal_hash),
    ]
    assert verify_events(events).valid

    leaked = events + [evidence_event("vmga_proposal_approved", proposal_id="p2", approval_token="raw")]
    result = verify_events(leaked)
    assert not result.valid
    assert "raw approval_token leaked" in result.errors[0]


def test_jsonl_ledger_and_cli_verifier_shape(tmp_path):
    ledger_path = tmp_path / "evidence.jsonl"
    ledger = JSONLVMGALedger(ledger_path)
    ledger.append(evidence_event("vmga_proposal_received", proposal_id="p1", policy_state="DENY", error_code="vmga_test"))
    assert ledger.read_all()[0]["proposal_id"] == "p1"
