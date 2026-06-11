from __future__ import annotations

import json

from vmga.evidence_integrity import (
    EvidenceCheckpoint,
    add_integrity_metadata,
    canonical_json_line,
    load_segmented_events,
    recover_one_ahead,
    verify_integrity,
)
from vmga.evidence import evidence_event
from vmga.ledger import JSONLVMGALedger, LedgerVestaAdapter
from vmga.sqlite_state import SQLiteStateStore
from vmga.vmga_adapter import VMGAGmailAdapter


KEY_ID = "operator-2026-06"
KEY = b"secret"
OLD_ID = "operator-2026-05"
OLD_KEY = b"old-secret"


def _signed_chain(count: int = 4, *, key_id: str = KEY_ID, key: bytes = KEY):
    records = []
    prev = None
    for sequence in range(1, count + 1):
        record = evidence_event("vmga_proposal_received", proposal_id=f"p{sequence}", policy_state="ALLOW")
        signed = add_integrity_metadata(record, key_id=key_id, key=key, sequence=sequence, prev_mac=prev)
        prev = signed["integrity"]["mac"]
        records.append(signed)
    return records


def _checkpoint(records) -> EvidenceCheckpoint:
    first = records[0]["integrity"]
    last = records[-1]["integrity"]
    return EvidenceCheckpoint(
        ledger_path="evidence.jsonl",
        genesis_sequence=first["sequence"],
        genesis_mac=first["mac"],
        last_sequence=last["sequence"],
        last_mac=last["mac"],
        key_id=last["key_id"],
    )


def _state(records, checkpoint=None, keyring=None):
    return verify_integrity(records, checkpoint=checkpoint or _checkpoint(records), keyring={KEY_ID: KEY} if keyring is None else keyring).state


def _reason(records, checkpoint=None, keyring=None):
    return verify_integrity(records, checkpoint=checkpoint or _checkpoint(records), keyring={KEY_ID: KEY} if keyring is None else keyring).reason


def test_hmac_chain_verified_intact():
    records = _signed_chain()
    assert _state(records) == "verified_intact"


def test_mutation_insertion_middle_deletion_reorder_and_tail_truncation_tamper():
    records = _signed_chain()
    mutated = [dict(record) for record in records]
    mutated[1] = json.loads(json.dumps(mutated[1]))
    mutated[1]["policy_state"] = "DENY"
    assert _state(mutated, _checkpoint(records)) == "verified_tampered"

    inserted = records[:2] + [_signed_chain(1)[0]] + records[2:]
    assert _state(inserted, _checkpoint(records)) == "verified_tampered"

    deleted = records[:1] + records[2:]
    assert _state(deleted, _checkpoint(records)) == "verified_tampered"

    reordered = [records[0], records[2], records[1], records[3]]
    assert _state(reordered, _checkpoint(records)) == "verified_tampered"

    truncated = records[:-1]
    assert _reason(truncated, _checkpoint(records)) == "head_mismatch"

    assert _state([], _checkpoint(records)) == "verified_tampered"
    assert _reason([], _checkpoint(records)) == "empty_ledger_with_expected_head"


def test_prefix_truncation_and_forged_genesis_tamper():
    records = _signed_chain()
    assert _reason(records[1:], _checkpoint(records)) == "genesis_mismatch"

    forged = [json.loads(json.dumps(record)) for record in records[1:]]
    forged[0] = add_integrity_metadata(
        {k: v for k, v in forged[0].items() if k != "integrity"},
        key_id=KEY_ID,
        key=KEY,
        sequence=1,
        prev_mac=None,
    )
    assert _state(forged, _checkpoint(records)) == "verified_tampered"


def test_unknown_key_missing_key_missing_head_and_legacy_no_metadata():
    records = _signed_chain()
    assert _reason(records, keyring={}) == "unknown_key_id"
    assert verify_integrity(records, checkpoint=None, keyring={KEY_ID: KEY}).reason == "missing_expected_head"
    legacy = [evidence_event("vmga_proposal_received", proposal_id="legacy", policy_state="ALLOW")]
    assert verify_integrity(legacy, checkpoint=None, keyring={KEY_ID: KEY}).reason == "missing_integrity_metadata"


def test_key_rotation_uses_per_record_key_id():
    records = _signed_chain(2, key_id=OLD_ID, key=OLD_KEY)
    prev = records[-1]["integrity"]["mac"]
    for sequence in range(3, 5):
        signed = add_integrity_metadata(
            evidence_event("vmga_proposal_received", proposal_id=f"p{sequence}", policy_state="ALLOW"),
            key_id=KEY_ID,
            key=KEY,
            sequence=sequence,
            prev_mac=prev,
        )
        prev = signed["integrity"]["mac"]
        records.append(signed)
    assert verify_integrity(records, checkpoint=_checkpoint(records), keyring={OLD_ID: OLD_KEY, KEY_ID: KEY}).state == "verified_intact"
    assert verify_integrity(records, checkpoint=_checkpoint(records), keyring={KEY_ID: KEY}).reason == "unknown_key_id"


def test_cross_file_rotation_continuity_and_deleted_segment(tmp_path):
    records = _signed_chain(4)
    base = tmp_path / "evidence.jsonl"
    (tmp_path / "evidence.jsonl.2").write_text(canonical_json_line(records[0]), encoding="utf-8")
    (tmp_path / "evidence.jsonl.1").write_text(canonical_json_line(records[1]), encoding="utf-8")
    base.write_text(canonical_json_line(records[2]) + canonical_json_line(records[3]), encoding="utf-8")

    loaded = load_segmented_events(base)
    assert _state(loaded, _checkpoint(records)) == "verified_intact"

    (tmp_path / "evidence.jsonl.1").unlink()
    loaded_after_gap = load_segmented_events(base)
    assert _state(loaded_after_gap, _checkpoint(records)) == "verified_tampered"


def test_crash_after_append_one_ahead_recovers_two_ahead_does_not():
    records = _signed_chain(3)
    checkpoint = _checkpoint(records[:2])
    recovered = recover_one_ahead(records, checkpoint=checkpoint, keyring={KEY_ID: KEY}, ledger_path="evidence.jsonl")
    assert recovered is not None
    assert recovered.last_sequence == 3

    records4 = _signed_chain(4)
    assert recover_one_ahead(records4, checkpoint=checkpoint, keyring={KEY_ID: KEY}, ledger_path="evidence.jsonl") is None


def test_adapter_opt_in_hmac_writes_checkpoint_and_recovers_one_ahead(tmp_path, monkeypatch):
    monkeypatch.setenv("VMGA_EVIDENCE_HMAC_KEY", "secret")
    monkeypatch.setenv("VMGA_EVIDENCE_HMAC_KEY_ID", KEY_ID)
    state = SQLiteStateStore(str(tmp_path / "state.sqlite3"))
    ledger = JSONLVMGALedger(tmp_path / "evidence.jsonl")
    adapter = VMGAGmailAdapter(
        vesta_adapter=LedgerVestaAdapter(ledger),
        profile="draft_assist",
        policy_rules={"ledger_required_for_kinetic": True},
        state_store=state,
        approval_secret="approval",
    )
    assert adapter._write_to_ledger(evidence_event("vmga_proposal_received", proposal_id="p1", policy_state="ALLOW"))
    head = state.load_evidence_head()
    assert head is not None
    assert head.last_sequence == 1
    assert "integrity" in ledger.read_all()[0]

    extra = add_integrity_metadata(
        evidence_event("vmga_proposal_received", proposal_id="p2", policy_state="ALLOW"),
        key_id=KEY_ID,
        key=KEY,
        sequence=2,
        prev_mac=head.last_mac,
    )
    ledger.append_line(canonical_json_line(extra))
    VMGAGmailAdapter(
        vesta_adapter=LedgerVestaAdapter(ledger),
        profile="draft_assist",
        policy_rules={"ledger_required_for_kinetic": True},
        state_store=state,
        approval_secret="approval",
    )
    assert state.load_evidence_head().last_sequence == 2
