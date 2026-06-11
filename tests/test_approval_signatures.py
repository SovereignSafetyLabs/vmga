from __future__ import annotations

import base64
import tempfile
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from vmga.vmga_adapter import VMGAGmailAdapter, VMGAStateStore


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


def _key_entry(key: Ed25519PrivateKey, key_id: str, status: str = "active", algorithm: str = "ed25519"):
    public_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "key_id": key_id,
        "algorithm": algorithm,
        "status": status,
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
    }


def _adapter(tmpdir, keyring):
    return VMGAGmailAdapter(
        vesta_adapter=MockVesta(),
        profile="draft_assist",
        policy_rules={
            "allowed_actions": ["create_draft"],
            "kinetic_requires_approval": True,
            "approval_workflow": {"approver_allowlist": ["operator_1"], "expiration": "3600"},
        },
        state_store=VMGAStateStore(tmpdir),
        approval_auth="signature",
        approval_public_keys=keyring,
        strict_mode=True,
    )


def _proposal(adapter):
    result = adapter.propose_action(
        action="create_draft",
        actor_id="agent_1",
        content="Draft",
        justification="Test",
    )
    assert result["status"] == "REVIEW_REQUIRED"
    return result


def _signed(adapter, key, proposal, nonce="nonce-1234567890abcdef", key_id="operator-current", **overrides):
    payload = adapter.approval_signature_payload(
        proposal["proposal_id"],
        overrides.get("approver_id", "operator_1"),
        time_window=overrides.get("time_window", VMGAGmailAdapter.approval_time_window()),
        approval_nonce=overrides.get("approval_nonce", nonce),
        key_id=overrides.get("key_id", key_id),
        signature_version=overrides.get("signature_version", "vmga-approval-ed25519-v1"),
    )
    if "proposal_hash" in overrides:
        payload["proposal_hash"] = overrides["proposal_hash"]
    signature = key.sign(VMGAGmailAdapter.canonical_approval_signature_payload(payload))
    return {
        "signature": base64.b64encode(signature).decode("ascii"),
        "time_window": payload["time_window"],
        "approval_nonce": payload["approval_nonce"],
        "key_id": payload["key_id"],
        "signature_version": payload["signature_version"],
    }


def test_valid_ed25519_signature_approval_persists_detached_signature():
    key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current")]})
        proposal = _proposal(adapter)
        signed = _signed(adapter, key, proposal)

        approved = adapter.approve_proposal(proposal["proposal_id"], "operator_1", **signed)

        assert approved["status"] == "APPROVED"
        record = adapter.approvals[proposal["proposal_id"]]
        assert record.approval_auth == "signature"
        assert record.signature == signed["signature"]
        assert record.signature_payload["proposal_hash"] == proposal["proposal_hash"]
        assert "expires_at" not in record.signature_payload
        assert record.binding_hash == record.expected_binding_hash()
        approved_events = [
            e for e in adapter.vesta.audit_ledger.events
            if e["event_type"] == "vmga_proposal_approved"
        ]
        assert len(approved_events) == 1
        evidence = approved_events[0]
        assert evidence["approval_auth"] == "signature"
        assert evidence["approval_signature"]["signature"] == signed["signature"]
        assert evidence["approval_signature"]["signed_payload"] == record.signature_payload
        assert evidence["approval_signature"]["key_id"] == "operator-current"
        assert adapter.execute_approved(proposal["proposal_id"], proposal["proposal_hash"], "", lambda x: {"ok": True})["status"] == "SUCCESS"


def test_wrong_key_and_tampered_message_are_denied():
    key = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current")]})
        proposal = _proposal(adapter)
        signed = _signed(adapter, wrong, proposal)
        assert adapter.approve_proposal(proposal["proposal_id"], "operator_1", **signed)["error_code"] == "vmga_signature_invalid"

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current")]})
        proposal = _proposal(adapter)
        signed = _signed(adapter, key, proposal, proposal_hash="sha256:tampered")
        assert adapter.approve_proposal(proposal["proposal_id"], "operator_1", **signed)["error_code"] == "vmga_signature_invalid"


def test_expired_signature_replayed_nonce_unknown_approver_and_missing_key_denied():
    key = Ed25519PrivateKey.generate()
    old_window = VMGAGmailAdapter.approval_time_window(datetime.now(timezone.utc) - timedelta(hours=1))
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current")]})
        proposal = _proposal(adapter)
        expired = _signed(adapter, key, proposal, time_window=old_window)
        assert adapter.approve_proposal(proposal["proposal_id"], "operator_1", **expired)["error_code"] == "vmga_signature_expired"

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current")]})
        first = _proposal(adapter)
        signed = _signed(adapter, key, first)
        assert adapter.approve_proposal(first["proposal_id"], "operator_1", **signed)["status"] == "APPROVED"
        second = _proposal(adapter)
        replay = _signed(adapter, key, second)
        assert adapter.approve_proposal(second["proposal_id"], "operator_1", **replay)["error_code"] == "vmga_signature_nonce_replay"

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current")]})
        proposal = _proposal(adapter)
        signed = _signed(adapter, key, proposal, approver_id="unknown")
        assert adapter.approve_proposal(proposal["proposal_id"], "unknown", **signed)["error_code"] == "vmga_approver_unauthorized"

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {})
        proposal = _proposal(adapter)
        signed = _signed(adapter, key, proposal)
        assert adapter.approve_proposal(proposal["proposal_id"], "operator_1", **signed)["error_code"] == "vmga_signature_keyring_missing"


def test_key_rotation_old_key_historical_verify_and_removed_key_denial():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory() as tmpdir:
        keyring = {"operator_1": [_key_entry(old, "operator-old"), _key_entry(new, "operator-current")]}
        adapter = _adapter(tmpdir, keyring)
        old_proposal = _proposal(adapter)
        old_signed = _signed(adapter, old, old_proposal, nonce="nonce-old-1234567890", key_id="operator-old")
        assert adapter.approve_proposal(old_proposal["proposal_id"], "operator_1", **old_signed)["status"] == "APPROVED"
        assert adapter.execute_approved(old_proposal["proposal_id"], old_proposal["proposal_hash"], "", lambda x: {"ok": True})["status"] == "SUCCESS"

        new_proposal = _proposal(adapter)
        new_signed = _signed(adapter, new, new_proposal, nonce="nonce-new-1234567890", key_id="operator-current")
        assert adapter.approve_proposal(new_proposal["proposal_id"], "operator_1", **new_signed)["status"] == "APPROVED"

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(old, "operator-old", status="removed")]})
        proposal = _proposal(adapter)
        signed = _signed(adapter, old, proposal, key_id="operator-old")
        assert adapter.approve_proposal(proposal["proposal_id"], "operator_1", **signed)["error_code"] == "vmga_signature_key_inactive"


def test_algorithm_mismatch_is_denied():
    key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = _adapter(tmpdir, {"operator_1": [_key_entry(key, "operator-current", algorithm="ecdsa-p256")]})
        proposal = _proposal(adapter)
        signed = _signed(adapter, key, proposal)
        assert adapter.approve_proposal(proposal["proposal_id"], "operator_1", **signed)["error_code"] == "vmga_signature_algorithm_mismatch"


def test_private_key_never_needed_by_broker_signer_payload_can_be_cli_signed(tmp_path, capsys):
    from vmga.cli import approval_sign_main

    key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "operator.pem"
    private_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )

    result = approval_sign_main([
        "--proposal-id", "p1",
        "--proposal-hash", "sha256:abc",
        "--approver-id", "operator_1",
        "--key-id", "operator-current",
        "--nonce", "nonce-cli-1234567890",
        "--private-key", str(private_path),
        "--time-window", "2026-06-10-12-00",
    ])

    assert result == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["proposal_id"] == "p1"
    assert payload["signature"]
