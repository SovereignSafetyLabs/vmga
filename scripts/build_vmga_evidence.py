#!/usr/bin/env python3
"""Build a safe VMGA dry-run evidence bundle using the fake backend."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"

import sys

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vmga import FakeGmailBackend, VMGAExecutor, VMGAGmailAdapter
from vmga.evidence import verify_events
from vmga.ledger import JSONLVMGALedger, LedgerVestaAdapter
from vmga.sqlite_state import SQLiteStateStore


def _append_json(path: Path, name: str, payload: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"name": name, "payload": payload}, sort_keys=True) + "\n")


def build_bundle(out_dir: Path, *, force: bool = False) -> int:
    if out_dir.exists() and force:
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = out_dir / "evidence.jsonl"
    transcript_path = out_dir / "dry_run_transcript.jsonl"
    state_path = out_dir / "vmga.sqlite3"

    ledger = JSONLVMGALedger(evidence_path)
    vesta = LedgerVestaAdapter(ledger)
    state = SQLiteStateStore(str(state_path))
    adapter = VMGAGmailAdapter(
        vesta_adapter=vesta,
        profile="scoped_execution",
        policy_rules={
            "allowed_actions": ["read", "create_draft"],
            "denied_actions": ["send"],
            "kinetic_requires_approval": True,
            "lockdown_threshold": 2,
            "domain_policy": {"internal_domains": ["example.com"], "external_domain_deny": False},
            "draft_policy": {"require_justification": True, "allow_external_recipients": True},
        },
        state_store=state,
        approval_secret="dry_run_secret",
    )
    executor = VMGAExecutor(adapter, FakeGmailBackend())

    allow = adapter.propose_action("read", "dry_agent", thread_id="thread_allow")
    _append_json(transcript_path, "allow_read", allow)

    review = adapter.propose_action(
        "create_draft",
        "dry_agent",
        thread_id="thread_review",
        message_ids=["msg_1"],
        recipients=["ops@example.com"],
        content="Draft response",
        justification="Dry-run approval path",
    )
    _append_json(transcript_path, "review_required", review)

    token = adapter.compute_approval_token(review["proposal_id"], review["proposal_hash"], "operator_1")
    approved = adapter.approve_proposal(review["proposal_id"], "operator_1", token)
    _append_json(transcript_path, "approved", approved)

    executed = executor.execute_approved(review["proposal_id"], review["proposal_hash"], token)
    _append_json(transcript_path, "executed", executed)

    replay = executor.execute_approved(review["proposal_id"], review["proposal_hash"], token)
    _append_json(transcript_path, "replay_denied", replay)

    tamper_review = adapter.propose_action(
        "create_draft",
        "dry_agent",
        thread_id="thread_tamper",
        recipients=["ops@example.com"],
        content="Tamper draft",
        justification="Dry-run tamper path",
    )
    tamper_token = adapter.compute_approval_token(tamper_review["proposal_id"], tamper_review["proposal_hash"], "operator_1")
    adapter.approve_proposal(tamper_review["proposal_id"], "operator_1", tamper_token)
    tamper = executor.execute_approved(tamper_review["proposal_id"], "sha256:" + "0" * 64, tamper_token)
    _append_json(transcript_path, "tamper_denied", tamper)

    denied = adapter.propose_action("send", "dry_bad_actor", recipients=["outside@example.invalid"], content="Do it")
    _append_json(transcript_path, "send_denied", denied)
    lockdown = adapter.propose_action("send", "dry_bad_actor", recipients=["outside@example.invalid"], content="Do it again")
    _append_json(transcript_path, "lockdown", lockdown)
    reset = adapter.reset_lockdown("dry_admin")
    _append_json(transcript_path, "reset", reset)

    verification = verify_events(ledger.read_all()).to_dict()
    (out_dir / "verification.json").write_text(json.dumps(verification, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if verification["valid"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Build VMGA fake-backend dry-run evidence")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "vmga-dry-run")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    return build_bundle(args.out, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
