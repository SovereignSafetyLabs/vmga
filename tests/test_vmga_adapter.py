"""Tests for VMGA Gmail adapter."""

import hashlib
import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from vmga.vmga_adapter import (
    VMGAProposal, VMGAPolicy, VMGAGmailAdapter, VMGAStateStore,
    GmailAction, ActionClass, ContentRisk, ApprovalRecord, load_vmga_policy
)


class TestVMGAProposal:
    def test_canonical_json_determinism(self):
        p1 = VMGAProposal(
            proposal_id="prop_123", action=GmailAction.CREATE_DRAFT, actor_id="agent_1",
            recipients=["z@example.com", "a@example.com"], content="Test draft"
        )
        p2 = VMGAProposal(
            proposal_id="prop_123", action=GmailAction.CREATE_DRAFT, actor_id="agent_1",
            recipients=["a@example.com", "z@example.com"], content="Test draft"
        )
        assert p1.canonical_json() == p2.canonical_json()
        assert p1.compute_hash() == p2.compute_hash()
    
    def test_hash_changes_on_content_mutation(self):
        p1 = VMGAProposal(proposal_id="prop_123", action=GmailAction.CREATE_DRAFT, actor_id="agent_1", content="Original")
        p2 = VMGAProposal(proposal_id="prop_123", action=GmailAction.CREATE_DRAFT, actor_id="agent_1", content="MALICIOUS")
        assert p1.compute_hash() != p2.compute_hash()
    
    def test_serialization_roundtrip(self):
        p1 = VMGAProposal(
            proposal_id="prop_123", action=GmailAction.CREATE_DRAFT, actor_id="agent_1",
            thread_id="thread_456", message_ids=["msg1", "msg2"],
            content="Draft", recipients=["a@example.com"], justification="Testing"
        )
        p2 = VMGAProposal.from_dict(p1.to_dict())
        assert p1.compute_hash() == p2.compute_hash()


class TestVMGAPolicy:
    def test_non_kinetic_classification(self):
        policy = VMGAPolicy("test", {})
        assert policy.classify_action(GmailAction.READ) == ActionClass.NON_KINETIC
        assert policy.classify_action(GmailAction.CREATE_DRAFT) == ActionClass.KINETIC
    
    def test_payment_mention_risk(self):
        policy = VMGAPolicy("test", {"domain_policy": {"internal_domains": ["company.com"]}})
        content = "Please process this invoice immediately. Wire transfer..."
        risk = policy.evaluate_content_risk(content, "client@example.com", [])
        assert risk.payment_mention == True
        assert risk.urgency_language == True
        assert risk.unknown_sender == True
    
    def test_external_recipient_detection(self):
        policy = VMGAPolicy("test", {"domain_policy": {"internal_domains": ["company.com"]}})
        risk = policy.evaluate_content_risk("Hello", "colleague@company.com", ["internal@company.com", "external@gmail.com"])
        assert risk.external_recipient == True
        assert risk.unknown_sender == False
    
    def test_allowed_actions_enforcement(self):
        rules = {"allowed_actions": ["read", "summarize"], "denied_actions": []}
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1")
        decision = policy.evaluate(proposal, ContentRisk())
        assert decision.allowed == False
        assert decision.rule_id == "vmga_not_allowed"
    
    def test_denied_actions_enforcement(self):
        rules = {"allowed_actions": ["send"], "denied_actions": ["send"]}
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.SEND, actor_id="agent_1", recipients=["to@test.com"])
        decision = policy.evaluate(proposal, ContentRisk())
        assert decision.allowed == False
        assert decision.rule_id == "vmga_explicit_deny"
    
    def test_draft_policy_max_length(self):
        rules = {"allowed_actions": ["create_draft"], "draft_policy": {"max_length": 100, "require_justification": False}}
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1", content="x" * 101)
        decision = policy.evaluate(proposal, ContentRisk())
        assert decision.allowed == False
        assert decision.rule_id == "vmga_draft_length_exceeded"
    
    def test_draft_policy_justification_required(self):
        rules = {"allowed_actions": ["create_draft"], "draft_policy": {"require_justification": True}}
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1", content="Draft", justification="")
        decision = policy.evaluate(proposal, ContentRisk())
        assert decision.allowed == False
        assert decision.rule_id == "vmga_draft_justification_required"
    
    def test_draft_policy_external_recipient(self):
        rules = {
            "allowed_actions": ["create_draft"],
            "draft_policy": {"allow_external_recipients": False, "require_justification": False},
            "domain_policy": {"internal_domains": ["company.com"]}
        }
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1", recipients=["external@gmail.com"])
        content_risk = ContentRisk(external_recipient=True)
        decision = policy.evaluate(proposal, content_risk)
        assert decision.allowed == False
        assert decision.rule_id == "vmga_draft_external_recipient_deny"
    
    def test_mfa_recovery_baseline_deny(self):
        rules = {"allowed_actions": ["send"], "baseline_denies": {"mfa_recovery_handling": True}}
        policy = VMGAPolicy("test", rules)
        content = "Your MFA recovery code is 123456"
        risk = policy.evaluate_content_risk(content, "sender@test.com", [])
        assert risk.mfa_recovery == True
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.SEND, actor_id="agent_1", recipients=["to@test.com"])
        decision = policy.evaluate(proposal, risk)
        assert decision.allowed == False
        assert decision.rule_id == "vmga_baseline_mfa_deny"
    
    def test_bulk_operation_baseline_deny(self):
        rules = {"allowed_actions": ["send"], "baseline_denies": {"bulk_forwarding": True}}
        policy = VMGAPolicy("test", rules)
        recipients = [f"user{i}@test.com" for i in range(15)]
        risk = policy.evaluate_content_risk("Hello", "sender@test.com", recipients)
        assert risk.bulk_operation == True
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.SEND, actor_id="agent_1", recipients=recipients)
        decision = policy.evaluate(proposal, risk)
        assert decision.allowed == False
        assert decision.rule_id == "vmga_baseline_bulk_deny"
    
    def test_per_action_approval_config(self):
        rules = {"allowed_actions": ["create_draft", "archive"], "approval_required": {"create_draft": True, "archive": False}}
        policy = VMGAPolicy("test", rules)
        assert policy.approval_required_per_action.get("archive") == False
    
    def test_invalid_action_string_returns_none(self):
        assert GmailAction.from_string("invalid") is None
        assert GmailAction.from_string("CREATE_DRAFT") == GmailAction.CREATE_DRAFT

    def test_unknown_policy_field_rejected(self):
        with pytest.raises(ValueError, match="Unknown VMGA policy field"):
            VMGAPolicy("test", {"allowed_actions": ["read"], "silent_allow_send": True})

    def test_unknown_nested_policy_field_rejected(self):
        with pytest.raises(ValueError, match="under 'draft_policy'"):
            VMGAPolicy("test", {"draft_policy": {"max_length": 100, "approve_later": True}})

    def test_unknown_policy_action_rejected(self):
        with pytest.raises(ValueError, match="Unknown VMGA action"):
            VMGAPolicy("test", {"allowed_actions": ["read", "send_everything"]})

    def test_policy_decision_has_stable_error_code(self):
        policy = VMGAPolicy("test", {"allowed_actions": ["read"]})
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.SEND, actor_id="agent_1")
        decision = policy.evaluate(proposal, ContentRisk())
        assert decision.allowed == False
        assert decision.rule_id == "vmga_not_allowed"
        assert decision.error_code == "vmga_not_allowed"

    def test_non_kinetic_read_allows_unknown_sender_risk(self):
        rules = {
            "allowed_actions": ["read"],
            "content_analysis": {"enforce_risk_threshold": True, "max_risk_score_auto_allow": 0},
        }
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.READ, actor_id="agent_1")
        decision = policy.evaluate(proposal, ContentRisk(unknown_sender=True))
        assert decision.allowed == True
        assert decision.rule_id == "vmga_non_kinetic_allow"

    def test_kinetic_draft_still_requires_review_with_risk_threshold(self):
        rules = {
            "allowed_actions": ["create_draft"],
            "kinetic_requires_approval": True,
            "draft_policy": {"require_justification": False, "allow_external_recipients": True},
            "content_analysis": {"enforce_risk_threshold": True, "max_risk_score_auto_allow": 0},
            "high_risk_indicators": ["payment_mention"],
        }
        policy = VMGAPolicy("test", rules)
        proposal = VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1")
        decision = policy.evaluate(proposal, ContentRisk(payment_mention=True))
        assert decision.allowed == False
        assert decision.rule_id == "vmga_high_risk_review_required"

    def test_policy_loader_validates_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "bad_policy.yaml"
            policy_path.write_text("allowed_actions: [read]\nsilent_allow_send: true\n")
            with pytest.raises(ValueError, match="Unknown VMGA policy field"):
                load_vmga_policy(str(policy_path))


class MockVesta:
    def __init__(self):
        self.audit_ledger = MockLedger()
    
    def execute(self, request, handler):
        class Result:
            request_id = getattr(request, 'request_id', "req_123")
            duration_ms = 100
        return Result()


class MockLedger:
    def __init__(self):
        self.events = []
    
    def append(self, event):
        self.events.append(event)


class TestVMGAGmailAdapter:
    def test_propose_non_kinetic_returns_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="observe_only",
                policy_rules={"allowed_actions": ["read", "summarize"]},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
        result = adapter.propose_action(action="read", actor_id="agent_1", thread_id="thread_123")
        assert result["status"] == "ALLOW"
        assert any(e["event_type"] == "vmga_proposal_received" for e in adapter.vesta.audit_ledger.events)
    
    def test_propose_draft_returns_review_required(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["read", "create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(
                action="create_draft", actor_id="agent_1", thread_id="thread_123",
                content="Draft reply", recipients=["client@company.com"], justification="Responding"
            )
            assert result["status"] == "REVIEW_REQUIRED"
            assert result["rule_id"] == "vmga_kinetic_approval_required"
    
    def test_invalid_action_returns_deny(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"]},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="invalid_action_xyz", actor_id="agent_1")
            assert result["status"] == "DENY"
            assert result["rule_id"] == "vmga_invalid_action"
            assert result["error_code"] == "vmga_invalid_action"
    
    def test_approve_proposal_binding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            # Compute token (out-of-band service would do this)
            token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            
            approval = adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)
            assert approval["status"] == "APPROVED"
            assert approval["proposal_hash"] == proposal_hash
            record = adapter.approvals[proposal_id]
            assert record.actor_id == "agent_1"
            assert record.action == "create_draft"
            assert record.binding_hash == record.expected_binding_hash()
            assert any(e["event_type"] == "vmga_proposal_approved" for e in adapter.vesta.audit_ledger.events)

    def test_expired_approval_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)

            expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            approval = adapter.approvals[proposal_id]
            approval.expires_at = expired_at
            approval.binding_hash = approval.expected_binding_hash()

            exec_result = adapter.execute_approved(proposal_id, proposal_hash, token, lambda x: x)
            assert exec_result["status"] == "DENY"
            assert exec_result["error_code"] == "vmga_approval_expired"

    def test_tampered_approval_binding_rejected_after_restart(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(
                action="create_draft", actor_id="agent_1", thread_id="thread_123",
                content="Draft", recipients=["client@company.com"], justification="Test"
            )
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)

            approval = adapter.approvals[proposal_id]
            approval.action = "send"
            adapter._save_state()

            restarted = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            exec_result = restarted.execute_approved(proposal_id, proposal_hash, token, lambda x: x)
            assert exec_result["status"] == "DENY"
            assert exec_result["error_code"] == "vmga_approval_binding_mismatch"
    
    def test_approve_without_token_fails(self):
        """Approval without token is rejected in strict mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret", strict_mode=True
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            
            # Try to approve without token
            with pytest.raises(TypeError):
                # approval_token is now a required argument
                adapter.approve_proposal(proposal_id, approver_id="operator_1")
    
    def test_approval_token_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True, "approval_workflow": {"approver_allowlist": ["operator_1"]}},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            approval = adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)
            assert approval["status"] == "APPROVED"
            
            # Unauthorized approver
            result2 = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft 2", justification="Test")
            token2 = adapter.compute_approval_token(result2["proposal_id"], result2["proposal_hash"], "unauthorized")
            approval2 = adapter.approve_proposal(result2["proposal_id"], approver_id="unauthorized", approval_token=token2)
            assert approval2["status"] == "DENY"
            assert approval2["error_code"] == "vmga_approver_unauthorized"
    
    def test_approval_with_wrong_token_rejected(self):
        """Forged approval tokens are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            # Create forged token with wrong secret (different adapter instance with different secret)
            forged_adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"]},
                state_store=VMGAStateStore(tmpdir), approval_secret="attacker_secret"
            )
            forged_token = forged_adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            
            result = adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=forged_token)
            assert result["status"] == "DENY"
            assert result["error_code"] == "vmga_approval_token_invalid"
    
    def test_file_write_attack_blocked(self):
        """Attacker cannot bypass HMAC by writing arbitrary token_hash to approvals file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create adapter with strict_mode and secret
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="legit_secret", strict_mode=True
            )
            
            # Create and approve a legitimate proposal
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            legit_token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=legit_token)
            
            # Now simulate attacker who can write to the state file
            # They modify the approval to have a different token_hash that matches their forged token
            attacker_token = "attacker_forged_token"
            attacker_hash = hashlib.sha256(attacker_token.encode()).hexdigest()[:32]
            
            # Attacker modifies the approvals file directly
            adapter.approvals[proposal_id].approval_token_hash = attacker_hash
            adapter._save_state()
            
            # New adapter instance loads the corrupted state
            adapter2 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="legit_secret", strict_mode=True
            )
            
            # Attacker tries to execute with their forged token
            # This should fail HMAC verification even though the hash matches
            exec_result = adapter2.execute_approved(proposal_id, proposal_hash, attacker_token, lambda x: x)
            assert exec_result["status"] == "DENY"
            assert "HMAC verification failed" in exec_result["error"]
    
    def test_non_strict_mode_allows_hash_only(self):
        """In non-strict mode, hash matching alone is sufficient (for backwards compatibility)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="secret", strict_mode=False
            )
            
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            # Approve normally
            token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)
            
            # Should succeed in non-strict mode
            exec_result = adapter.execute_approved(proposal_id, proposal_hash, token, lambda x: x)
            assert exec_result["status"] == "SUCCESS"
    
    def test_one_time_use(self):
        """Approval can only be used once."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)
            
            # First execution succeeds
            exec_result = adapter.execute_approved(proposal_id, proposal_hash, token, lambda x: x)
            assert exec_result["status"] == "SUCCESS"
            
            # Second execution fails (already used)
            exec_result2 = adapter.execute_approved(proposal_id, proposal_hash, token, lambda x: x)
            assert exec_result2["status"] == "DENY"
            assert "already used" in exec_result2["error"].lower()
    
    def test_hash_mismatch_rejected(self):
        """Execution rejected if proposal hash doesn't match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Original", justification="Test")
            proposal_id = result["proposal_id"]
            original_hash = result["proposal_hash"]
            
            token = adapter.compute_approval_token(proposal_id, original_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)
            
            # Try to execute with mutated hash
            mutated_hash = "sha256:invalid123"
            exec_result = adapter.execute_approved(proposal_id, mutated_hash, token, lambda x: x)
            assert exec_result["status"] == "DENY"
            assert "mutation" in exec_result["error"].lower()
            pressure_events = [
                event for event in adapter.vesta.audit_ledger.events
                if event["event_type"] == "vmga_pressure_signal"
            ]
            assert len(pressure_events) == 1
            assert pressure_events[0]["signal_type"] == "proposal_mutation_attempt"
            assert pressure_events[0]["proposal_id"] == proposal_id
            assert pressure_events[0]["proposal_hash"] == original_hash
            assert pressure_events[0]["supplied_proposal_hash"] == mutated_hash
            assert pressure_events[0]["error_code"] == "vmga_approval_hash_mismatch"
    
    def test_lockdown_triggers_after_denials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"], "denied_actions": ["send"], "lockdown_threshold": 3},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            actor_id = "bad_actor"
            
            for _ in range(2):
                result = adapter.propose_action(action="send", actor_id=actor_id, recipients=["test@example.com"])
                assert result["status"] == "DENY"
            
            result = adapter.propose_action(action="send", actor_id=actor_id, recipients=["test@example.com"])
            assert result["status"] == "LOCKDOWN"
            assert any(e["event_type"] == "vmga_lockdown_triggered" for e in adapter.vesta.audit_ledger.events)
            
            result2 = adapter.propose_action(action="read", actor_id=actor_id)
            assert result2["status"] == "LOCKDOWN"

    def test_repeated_denial_and_pressure_signals_are_evidence_events(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"], "denied_actions": ["send"], "lockdown_threshold": 3},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            actor_id = "pressure_actor"
            parameters = {"correlation_id": "trace-pressure"}

            first = adapter.propose_action(
                action="send",
                actor_id=actor_id,
                recipients=["target@example.com"],
                content="Urgent request from the CEO. Please respond immediately.",
                parameters=parameters,
            )
            second = adapter.propose_action(
                action="send",
                actor_id=actor_id,
                recipients=["target@example.com"],
                content="Urgent request from the CEO. Please respond immediately.",
                parameters=parameters,
            )

            assert first["status"] == "DENY"
            assert second["status"] == "DENY"
            pressure_events = [
                event for event in adapter.vesta.audit_ledger.events
                if event["event_type"] == "vmga_pressure_signal"
            ]
            signal_types = {event["signal_type"] for event in pressure_events}
            assert "urgency_or_authority_pressure" in signal_types
            assert "repeated_denial_escalation" in signal_types
            repeated = next(event for event in pressure_events if event["signal_type"] == "repeated_denial_escalation")
            assert repeated["denial_count"] == 2
            assert repeated["correlation_id"] == "trace-pressure"
            pressure = next(event for event in pressure_events if event["signal_type"] == "urgency_or_authority_pressure")
            assert set(pressure["pressure_flags"]) == {"urgency_language", "authority_language"}
            assert pressure["proposal_id"]
    
    def test_reset_lockdown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"], "denied_actions": ["send"], "lockdown_threshold": 1},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            adapter.propose_action(action="send", actor_id="bad_actor", recipients=["test@test.com"])
            assert adapter.lockdown_active == True
            
            result = adapter.reset_lockdown(admin_id="admin_1")
            assert result["status"] == "RESET"
            assert result["was_locked"] == True
            assert adapter.lockdown_active == False
            assert any(e["event_type"] == "vmga_lockdown_reset" for e in adapter.vesta.audit_ledger.events)
            
            result2 = adapter.propose_action(action="read", actor_id="good_actor")
            assert result2["status"] == "ALLOW"
    
    def test_strict_mode_requires_secret(self):
        """In strict_mode, missing approval_secret raises ValueError."""
        with pytest.raises(ValueError, match="VMGA_APPROVAL_SECRET must be set"):
            VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"]},
                approval_secret=None, strict_mode=True
            )


class TestVMGAStateStore:
    def test_atomic_write_and_permissions(self):
        """State store uses atomic writes with restrictive permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VMGAStateStore(tmpdir)
            
            # Check directory permissions
            dir_stat = os.stat(store.storage_path)
            assert stat.S_IMODE(dir_stat.st_mode) == 0o700
            
            proposals = {"prop_1": VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1")}
            store.save_pending_proposals(proposals)
            
            # Check file permissions
            file_stat = os.stat(store.pending_path)
            assert stat.S_IMODE(file_stat.st_mode) == 0o600
    
    def test_save_and_load_pending_proposals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VMGAStateStore(tmpdir)
            proposals = {
                "prop_1": VMGAProposal(proposal_id="prop_1", action=GmailAction.CREATE_DRAFT, actor_id="agent_1", content="Draft 1"),
                "prop_2": VMGAProposal(proposal_id="prop_2", action=GmailAction.SEND, actor_id="agent_2", recipients=["to@test.com"])
            }
            store.save_pending_proposals(proposals)
            loaded = store.load_pending_proposals()
            assert len(loaded) == 2
            assert loaded["prop_1"].action == GmailAction.CREATE_DRAFT
    
    def test_save_and_load_approvals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VMGAStateStore(tmpdir)
            now = datetime.now(timezone.utc)
            approvals = {
                "prop_1": ApprovalRecord(
                    proposal_id="prop_1", proposal_hash="sha256:abc123", approver_id="operator_1",
                    approved_at=now.isoformat(), expires_at=(now + timedelta(hours=1)).isoformat(),
                    used=False, approval_token_hash="hash123"
                )
            }
            store.save_approvals(approvals)
            loaded = store.load_approvals()
            assert len(loaded) == 1
            assert loaded["prop_1"].used == False
    
    def test_adapter_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter1 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            
            result = adapter1.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            token = adapter1.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter1.approve_proposal(proposal_id, approver_id="operator_1", approval_token=token)
            
            # New adapter instance
            adapter2 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            
            assert proposal_id in adapter2.approvals
            assert adapter2.approvals[proposal_id].approver_id == "operator_1"
            
            # Execute with token
            exec_result = adapter2.execute_approved(proposal_id, proposal_hash, token, lambda x: x)
            assert exec_result["status"] == "SUCCESS"
    
    def test_lockdown_persists_across_restart(self):
        """LOCKDOWN state survives adapter restart."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create adapter and trigger lockdown
            adapter1 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"], "denied_actions": ["send"], "lockdown_threshold": 1},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            adapter1.propose_action(action="send", actor_id="bad_actor", recipients=["test@test.com"])
            assert adapter1.lockdown_active == True
            assert adapter1.denial_counts["bad_actor"] == 1
            
            # New adapter instance loads state
            adapter2 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"], "denied_actions": ["send"], "lockdown_threshold": 1},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret"
            )
            
            # Lockdown and denial counts persisted
            assert adapter2.lockdown_active == True
            assert adapter2.denial_counts.get("bad_actor") == 1
            
            # Still locked out
            result = adapter2.propose_action(action="read", actor_id="good_actor")
            assert result["status"] == "LOCKDOWN"
    
    def test_proposal_ttl_expires_old_proposals(self):
        """Old proposals are garbage collected on load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VMGAStateStore(tmpdir)
            
            # Create proposals with old timestamps
            old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
            recent_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            
            proposals = {
                "old_prop": VMGAProposal(
                    proposal_id="old_prop", action=GmailAction.CREATE_DRAFT,
                    actor_id="agent_1", content="Old", requested_at=old_time
                ),
                "recent_prop": VMGAProposal(
                    proposal_id="recent_prop", action=GmailAction.CREATE_DRAFT,
                    actor_id="agent_1", content="Recent", requested_at=recent_time
                )
            }
            store.save_pending_proposals(proposals, proposal_ttl_seconds=86400)  # 24h TTL
            
            # Load with TTL - old proposal should be GC'd
            loaded = store.load_pending_proposals(proposal_ttl_seconds=86400)
            assert "old_prop" not in loaded
            assert "recent_prop" in loaded
    
    def test_rate_limiting_on_bad_tokens(self):
        """Repeated invalid token attempts trigger rate limiting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir),
                approval_secret="test_secret", strict_mode=True
            )
            
            # Create and approve a proposal
            result = adapter.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            legit_token = adapter.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter.approve_proposal(proposal_id, approver_id="operator_1", approval_token=legit_token)
            
            # Try to execute with wrong tokens multiple times
            for i in range(5):
                result = adapter.execute_approved(proposal_id, proposal_hash, f"wrong_token_{i}", lambda x: x)
                assert result["status"] == "DENY"
            
            # 6th attempt should hit rate limit
            result = adapter.execute_approved(proposal_id, proposal_hash, "wrong_token_6", lambda x: x)
            assert result["status"] == "DENY"
            assert "Rate limit exceeded" in result["error"]
            
            # Even with correct token, still rate limited (lockout period)
            result = adapter.execute_approved(proposal_id, proposal_hash, legit_token, lambda x: x)
            assert result["status"] == "DENY"
            assert "Rate limit exceeded" in result["error"]
    
    def test_rate_limiting_persists_across_restart(self):
        """Rate limiting state survives adapter restart (prevents DOS-to-clear)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create adapter and trigger rate limiting
            adapter1 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret", strict_mode=True
            )
            
            result = adapter1.propose_action(action="create_draft", actor_id="agent_1", content="Draft", justification="Test")
            proposal_id = result["proposal_id"]
            proposal_hash = result["proposal_hash"]
            
            legit_token = adapter1.compute_approval_token(proposal_id, proposal_hash, "operator_1")
            adapter1.approve_proposal(proposal_id, approver_id="operator_1", approval_token=legit_token)
            
            # Trigger 5 failed attempts
            for i in range(5):
                adapter1.execute_approved(proposal_id, proposal_hash, f"wrong_{i}", lambda x: x)
            
            # Verify rate limited
            result = adapter1.execute_approved(proposal_id, proposal_hash, "wrong_5", lambda x: x)
            assert "Rate limit exceeded" in result["error"]
            
            # New adapter instance loads rate limit state
            adapter2 = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="draft_assist",
                policy_rules={"allowed_actions": ["create_draft"], "kinetic_requires_approval": True},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret", strict_mode=True
            )
            
            # Still rate limited after restart
            result = adapter2.execute_approved(proposal_id, proposal_hash, "wrong_6", lambda x: x)
            assert result["status"] == "DENY"
            assert "Rate limit exceeded" in result["error"]
    
    def test_state_size_limit_fail_closed(self):
        """Oversized state files trigger fail-closed behavior."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VMGAStateStore(tmpdir)
            
            # Create an oversized state file
            oversized_data = {"x": "y" * 10000000}  # ~10MB
            import json
            with open(store.pending_path, 'w') as f:
                json.dump(oversized_data, f)
            
            # Load with small size limit and fail-closed
            state = store.load_all_state(fail_closed=True, max_state_size_bytes=1000)
            
            assert state["corrupted"] == True
            assert state["lockdown_active"] == True
            assert state["pending_proposals"] == {}
    
    def test_fail_closed_on_corrupted_state(self):
        """Corrupted state triggers LOCKDOWN when fail_closed_on_corrupted_state=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a corrupted lockdown state file
            lockdown_path = Path(tmpdir) / "lockdown_state.json"
            lockdown_path.write_text("corrupted json{{{")
            
            # Load with fail-closed - should trigger lockdown
            adapter = VMGAGmailAdapter(
                vesta_adapter=MockVesta(), profile="test",
                policy_rules={"allowed_actions": ["read"]},
                state_store=VMGAStateStore(tmpdir), approval_secret="test_secret",
                fail_closed_on_corrupted_state=True
            )
            
            assert adapter.lockdown_active == True
            
            # All requests blocked
            result = adapter.propose_action(action="read", actor_id="agent_1")
            assert result["status"] == "LOCKDOWN"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
