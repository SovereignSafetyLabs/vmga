#!/usr/bin/env python3
"""Build a safe VMGA dry-run evidence bundle using the fake backend."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"

import sys

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vmga import FakeGmailBackend, VMGAExecutor, VMGAGmailAdapter
from vmga.evidence import verify_events
from vmga.ledger import JSONLVMGALedger, LedgerVestaAdapter
from vmga.redaction import redact_json, redact_text
from vmga.sqlite_state import SQLiteStateStore


def _append_json(path: Path, name: str, payload: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"name": name, "payload": payload}, sort_keys=True) + "\n")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _run_command(command: list[str], *, redactions: list[str], timeout: float = 10.0) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return {"status": "missing", "command": command}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": command}
    return {
        "status": "ok" if completed.returncode == 0 else "error",
        "command": command,
        "returncode": completed.returncode,
        "stdout": redact_text(completed.stdout.strip(), redactions)[:4000],
        "stderr": redact_text(completed.stderr.strip(), redactions)[:4000],
    }


def _broker_health(broker_url: str, *, redactions: list[str], timeout: float = 5.0) -> dict[str, Any]:
    try:
        req = request.Request(broker_url.rstrip("/") + "/health", method="GET", headers={"Accept": "application/json"})
        with request.urlopen(req, timeout=timeout) as response:
            return {"status": "ok", "payload": redact_json(json.loads(response.read().decode("utf-8")), redactions)}
    except (error.URLError, ValueError, TypeError) as exc:
        return {"status": "error", "error": redact_text(str(exc), redactions)}


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


def build_release_bundle(
    out_dir: Path,
    *,
    force: bool = False,
    broker_url: str = "http://127.0.0.1:8765",
    include_local_tools: bool = False,
    redact_value: list[str] | None = None,
) -> int:
    if out_dir.exists() and force:
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    redactions = redact_value or []
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": {
            "policies": {
                path.name: _sha256_file(path)
                for path in sorted((ROOT / "policies").glob("*.yaml"))
            },
            "examples": {
                path.name: _sha256_file(path)
                for path in sorted((ROOT / "examples").glob("*.yaml"))
            },
            "openclaw_plugin_manifest": _sha256_file(ROOT / "integrations" / "openclaw" / "openclaw.plugin.json"),
        },
        "broker_health": _broker_health(broker_url, redactions=redactions),
        "tool_versions": {},
        "operator_evidence_slots": {
            "gog_auth_health": "not_collected",
            "hermes_plugin_status": "not_collected",
            "openclaw_doctor": "not_collected",
            "openclaw_security_audit": "not_collected",
            "openclaw_secrets_audit": "not_collected",
            "openclaw_sandbox_explain": "not_collected",
            "openclaw_approvals": "not_collected",
            "openclaw_plugin_inspect": "not_collected",
            "direct_bypass_denial": "not_collected",
            "live_smoke_transcript": "not_collected",
        },
    }

    if include_local_tools:
        report["tool_versions"] = {
            "hermes": _run_command(["hermes", "--version"], redactions=redactions),
            "openclaw": _run_command(["openclaw", "--version"], redactions=redactions),
            "gog_agent_safe": _run_command(["gog-agent-safe", "--version"], redactions=redactions),
        }
        report["operator_evidence_slots"].update(
            {
                "hermes_plugin_status": _run_command(["hermes", "plugins", "list"], redactions=redactions, timeout=20.0),
                "openclaw_doctor": _run_command(["openclaw", "doctor"], redactions=redactions, timeout=30.0),
                "openclaw_plugin_inspect": _run_command(["openclaw", "plugins", "inspect", "plugin.vmga"], redactions=redactions),
            }
        )

    report = redact_json(report, redactions)
    (out_dir / "release_evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build VMGA fake-backend dry-run evidence")
    parser.add_argument("--mode", choices=["dry-run", "release"], default="dry-run")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "vmga-dry-run")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--broker-url", default="http://127.0.0.1:8765")
    parser.add_argument("--include-local-tools", action="store_true")
    parser.add_argument("--redact-value", action="append", default=[])
    args = parser.parse_args()
    if args.mode == "release":
        return build_release_bundle(
            args.out,
            force=args.force,
            broker_url=args.broker_url,
            include_local_tools=args.include_local_tools,
            redact_value=args.redact_value,
        )
    return build_bundle(args.out, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
