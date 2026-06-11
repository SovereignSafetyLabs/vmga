"""Finding 3: posture must verify enforcement modes are operative, not declared."""

from __future__ import annotations

import base64
import inspect
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import vmga.posture as posture_module
from vmga.evidence_integrity import add_integrity_metadata, canonical_json_line
from vmga.evidence import evidence_event
from vmga.posture import PostureConfig, assess_posture
from vmga.sqlite_state import SQLiteStateStore
from vmga.evidence_integrity import EvidenceCheckpoint

KEY_ID = "operator-2026-06"
KEY_SECRET = "posture-test-secret"


def _check(report, check_id):
    return next(item for item in report["checks"] if item["id"] == check_id)


def _write_chained_ledger(tmp_path, count=3):
    ledger_path = tmp_path / "evidence.jsonl"
    records = []
    prev = None
    for sequence in range(1, count + 1):
        record = evidence_event("vmga_proposal_received", proposal_id=f"p{sequence}", policy_state="ALLOW")
        signed = add_integrity_metadata(
            record, key_id=KEY_ID, key=KEY_SECRET.encode(), sequence=sequence, prev_mac=prev
        )
        prev = signed["integrity"]["mac"]
        records.append(signed)
    with open(ledger_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(canonical_json_line(record))
    return ledger_path, records


def _save_checkpoint(tmp_path, records, ledger_path):
    store = SQLiteStateStore(tmp_path / "state.sqlite3")
    store.save_evidence_head(EvidenceCheckpoint(
        ledger_path=str(ledger_path),
        genesis_sequence=records[0]["integrity"]["sequence"],
        genesis_mac=records[0]["integrity"]["mac"],
        last_sequence=records[-1]["integrity"]["sequence"],
        last_mac=records[-1]["integrity"]["mac"],
        key_id=KEY_ID,
    ))
    return tmp_path / "state.sqlite3"


def _chain_config(tmp_path, ledger_path, db_path):
    return PostureConfig(
        evidence_integrity="hmac_chain",
        ledger_path=str(ledger_path),
        state_db_path=str(db_path),
    )


def _set_evidence_env(monkeypatch):
    monkeypatch.setenv("VMGA_EVIDENCE_HMAC_KEY", KEY_SECRET)
    monkeypatch.setenv("VMGA_EVIDENCE_HMAC_KEY_ID", KEY_ID)


def test_signature_declared_without_keyring_is_warn_not_pass():
    report = assess_posture(PostureConfig(approval_auth="signature", signature_readiness=None))
    check = _check(report, "approval_boundary")
    assert check["status"] == "warn"
    assert "not operative" in check["summary"]

    report = assess_posture(PostureConfig(
        approval_auth="signature",
        signature_readiness={"state": "cannot_verify", "reason": "missing_approval_public_keys"},
    ))
    check = _check(report, "approval_boundary")
    assert check["status"] == "warn"
    assert check["detail"] == "missing_approval_public_keys"


def test_signature_with_operative_readiness_is_pass():
    report = assess_posture(PostureConfig(
        approval_auth="signature",
        signature_readiness={"state": "verified_intact", "reason": "active_ed25519_keyring_loaded"},
    ))
    check = _check(report, "approval_boundary")
    assert check["status"] == "pass"
    assert "operative" in check["summary"]


def test_adapter_signature_readiness_validates_keyring(tmp_path):
    from vmga.vmga_adapter import VMGAGmailAdapter, VMGAStateStore

    key = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")

    def adapter(keyring):
        return VMGAGmailAdapter(
            vesta_adapter=type("V", (), {"audit_ledger": None})(),
            profile="draft_assist",
            policy_rules={"allowed_actions": ["create_draft"]},
            state_store=VMGAStateStore(str(tmp_path / "state")),
            approval_auth="signature",
            approval_public_keys=keyring,
            strict_mode=True,
        )

    good = {"op": [{"key_id": "k1", "algorithm": "ed25519", "status": "active", "public_key": public_b64}]}
    assert adapter(good).signature_readiness["state"] == "verified_intact"

    inactive = {"op": [{"key_id": "k1", "algorithm": "ed25519", "status": "retired", "public_key": public_b64}]}
    assert adapter(inactive).signature_readiness == {"state": "cannot_verify", "reason": "no_active_keys"}

    garbage = {"op": [{"key_id": "k1", "algorithm": "ed25519", "status": "active", "public_key": "!!notakey"}]}
    assert adapter(garbage).signature_readiness["reason"] == "unparseable_public_key:k1"

    wrong_alg = {"op": [{"key_id": "k1", "algorithm": "rsa", "status": "active", "public_key": public_b64}]}
    assert adapter(wrong_alg).signature_readiness["reason"] == "unsupported_algorithm:k1"


def test_chain_declared_with_intact_ledger_is_pass(tmp_path, monkeypatch):
    _set_evidence_env(monkeypatch)
    ledger_path, records = _write_chained_ledger(tmp_path)
    db_path = _save_checkpoint(tmp_path, records, ledger_path)
    report = assess_posture(_chain_config(tmp_path, ledger_path, db_path))
    check = _check(report, "evidence_integrity")
    assert check["status"] == "pass"
    assert "operative" in check["summary"]


def test_chain_declared_with_tampered_ledger_is_fail_and_mode_advisory(tmp_path, monkeypatch):
    _set_evidence_env(monkeypatch)
    ledger_path, records = _write_chained_ledger(tmp_path)
    db_path = _save_checkpoint(tmp_path, records, ledger_path)
    mutated = json.loads(json.dumps(records[1]))
    mutated["policy_state"] = "DENY"
    lines = ledger_path.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[1] = canonical_json_line(mutated)
    ledger_path.write_text("".join(lines), encoding="utf-8")

    report = assess_posture(_chain_config(tmp_path, ledger_path, db_path))
    check = _check(report, "evidence_integrity")
    assert check["status"] == "fail"
    assert report["mode"] == "advisory"
    assert report["hard_enforcement_ready"] is False


def test_chain_declared_without_key_or_checkpoint_is_unknown_with_reason(tmp_path, monkeypatch):
    ledger_path, records = _write_chained_ledger(tmp_path)
    db_path = _save_checkpoint(tmp_path, records, ledger_path)

    monkeypatch.delenv("VMGA_EVIDENCE_HMAC_KEY", raising=False)
    monkeypatch.delenv("VMGA_EVIDENCE_HMAC_KEY_ID", raising=False)
    report = assess_posture(_chain_config(tmp_path, ledger_path, db_path))
    check = _check(report, "evidence_integrity")
    assert check["status"] == "unknown"
    assert "missing_evidence_hmac_key" in check["detail"]
    assert report["hard_enforcement_ready"] is False

    _set_evidence_env(monkeypatch)
    empty_db = tmp_path / "empty-state.sqlite3"
    report = assess_posture(_chain_config(tmp_path, ledger_path, empty_db))
    check = _check(report, "evidence_integrity")
    assert check["status"] == "unknown"
    assert "missing_expected_head" in check["detail"]


def test_legacy_modes_unchanged():
    report = assess_posture(PostureConfig(evidence_integrity="append_only"))
    check = _check(report, "evidence_integrity")
    assert check["status"] == "warn"

    report = assess_posture(PostureConfig(approval_auth="hmac"))
    check = _check(report, "approval_boundary")
    assert check["status"] == "warn"


def test_posture_warns_when_broker_process_is_root(monkeypatch):
    monkeypatch.setattr(posture_module.os, "geteuid", lambda: 0, raising=False)

    report = assess_posture(PostureConfig())

    check = _check(report, "process_privilege")
    assert check["status"] == "warn"
    assert "root" in check["summary"]
    assert report["hard_enforcement_ready"] is False


def test_posture_contains_no_reimplemented_verification():
    source = inspect.getsource(posture_module)
    # No second copy of either check: no MAC computation, no key parsing,
    # no crypto imports. Mentioning Ed25519 in operator-facing text is fine.
    assert "hmac.new" not in source
    assert "import hmac" not in source
    assert "cryptography" not in source
    assert "compute_record_mac" not in source
    assert "load_ed25519" not in source.lower()
    assert "verify_integrity" in source  # calls the single source of truth
