"""Command-line helpers for VMGA."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .backends import FakeGmailBackend, GogCLIBackend
from .broker import VMGABroker, make_server
from .evidence import load_jsonl_events, verify_events
from .executor import VMGAExecutor
from .ledger import JSONLVMGALedger, LedgerVestaAdapter
from .redaction import redact_json
from .sqlite_state import SQLiteStateStore
from .vmga_adapter import ApprovalRecord, VMGAGmailAdapter, VMGAProposal, load_vmga_policy


def verify_evidence_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify VMGA JSONL evidence")
    parser.add_argument("path", help="Path to VMGA evidence JSONL")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    args = parser.parse_args(argv)

    try:
        events = load_jsonl_events(args.path)
        result = verify_events(events)
    except Exception as exc:
        result = {"valid": False, "errors": [str(exc)], "warnings": []}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"VMGA evidence invalid: {exc}", file=sys.stderr)
        return 2

    payload = result.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    elif result.valid:
        print("VMGA evidence valid")
    else:
        print("VMGA evidence invalid", file=sys.stderr)
        for error in result.errors:
            print(f"- {error}", file=sys.stderr)
    return 0 if result.valid else 2


def _build_backend(args: argparse.Namespace):
    if args.backend == "fake":
        return FakeGmailBackend()
    return GogCLIBackend(
        binary=args.gog_binary,
        account=args.gog_account,
        client=args.gog_client,
        home=args.gog_home,
        timeout_seconds=args.gog_timeout,
    )


def approval_token_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute a VMGA approval token")
    parser.add_argument("proposal_id", help="VMGA proposal id")
    parser.add_argument("proposal_hash", help="VMGA proposal hash")
    parser.add_argument("approver_id", help="Approver id")
    parser.add_argument("--secret-env", default="VMGA_APPROVAL_SECRET", help="Env var containing approval HMAC secret")
    parser.add_argument("--time-window", default=None, help="UTC approval time window, YYYY-MM-DD-HH-MM")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    args = parser.parse_args(argv)

    approval_secret = os.getenv(args.secret_env)
    if not approval_secret:
        print(f"{args.secret_env} is required", file=sys.stderr)
        return 2

    time_window = args.time_window or VMGAGmailAdapter.approval_time_window(datetime.now(timezone.utc))
    message = f"{args.proposal_id}:{args.proposal_hash}:{args.approver_id}:{time_window}"
    token = hmac.new(approval_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    if args.json:
        print(json.dumps({
            "proposal_id": args.proposal_id,
            "proposal_hash": args.proposal_hash,
            "approver_id": args.approver_id,
            "time_window": time_window,
            "approval_token": token,
        }, indent=2, sort_keys=True))
    else:
        print(token)
    return 0


def _proposal_summary(proposal: VMGAProposal) -> dict[str, object]:
    return {
        "proposal_id": proposal.proposal_id,
        "proposal_hash": proposal.compute_hash(),
        "action": proposal.action.value,
        "actor_id": proposal.actor_id,
        "thread_id": proposal.thread_id,
        "message_count": len(proposal.message_ids),
        "recipient_count": len(proposal.recipients),
        "attachment_count": len(proposal.attachment_ids),
        "requested_at": proposal.requested_at,
        "has_content": bool(proposal.content),
    }


def _approval_summary(approval: ApprovalRecord) -> dict[str, object]:
    return {
        "proposal_id": approval.proposal_id,
        "proposal_hash": approval.proposal_hash,
        "action": approval.action,
        "actor_id": approval.actor_id,
        "approver_id": approval.approver_id,
        "expires_at": approval.expires_at,
        "used": approval.used,
        "message_count": len(approval.message_ids),
        "recipient_count": len(approval.recipients),
        "attachment_count": len(approval.attachment_ids),
        "has_content": bool(approval.content),
    }


def _print_payload(payload: object, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if isinstance(payload, list):
        for item in payload:
            print(" ".join(f"{key}={value}" for key, value in item.items()))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")


def _post_broker_json(broker_url: str, endpoint: str, payload: dict[str, object], bearer_token: str | None) -> dict[str, object]:
    from urllib import request

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    req = request.Request(
        broker_url.rstrip("/") + endpoint,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with request.urlopen(req, timeout=10.0) as response:
        return json.loads(response.read().decode("utf-8"))


def operator_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VMGA operator helper")
    parser.add_argument("--state-db", default=".vmga/state.sqlite3", help="SQLite state database path")
    parser.add_argument("--broker-url", default=os.getenv("VMGA_BROKER_URL", "http://127.0.0.1:8765"))
    parser.add_argument("--bearer-token-env", default="VMGA_BROKER_TOKEN")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List pending proposals and approvals")

    show = sub.add_parser("show", help="Show one proposal or approval")
    show.add_argument("proposal_id")
    show.add_argument("--verbose", action="store_true", help="Include redacted binding details")

    approve = sub.add_parser("approve", help="Submit an approval token to the broker")
    approve.add_argument("proposal_id")
    approve.add_argument("approver_id")
    approve.add_argument("approval_token")

    execute = sub.add_parser("execute", help="Execute an approved proposal through the broker")
    execute.add_argument("proposal_id")
    execute.add_argument("proposal_hash")
    execute.add_argument("approval_token")

    args = parser.parse_args(argv)
    bearer_token = os.getenv(args.bearer_token_env)

    if args.command in {"approve", "execute"}:
        endpoint = "/v1/approvals" if args.command == "approve" else "/v1/executions"
        if args.command == "approve":
            payload: dict[str, object] = {
                "proposal_id": args.proposal_id,
                "approver_id": args.approver_id,
                "approval_token": args.approval_token,
            }
        else:
            payload = {
                "proposal_id": args.proposal_id,
                "proposal_hash": args.proposal_hash,
                "approval_token": args.approval_token,
            }
        _print_payload(redact_json(_post_broker_json(args.broker_url, endpoint, payload, bearer_token)), as_json=args.json)
        return 0

    store = SQLiteStateStore(args.state_db)
    pending = store.load_pending_proposals()
    approvals = store.load_approvals()

    if args.command == "list":
        rows = [
            {"kind": "pending", **_proposal_summary(proposal)}
            for proposal in pending.values()
        ] + [
            {"kind": "approval", **_approval_summary(approval)}
            for approval in approvals.values()
        ]
        _print_payload(rows, as_json=args.json)
        return 0

    if args.proposal_id in pending:
        proposal = pending[args.proposal_id]
        payload = _proposal_summary(proposal)
        if args.verbose:
            payload["binding"] = redact_json(proposal.to_dict())
        _print_payload(payload, as_json=args.json)
        return 0

    if args.proposal_id in approvals:
        approval = approvals[args.proposal_id]
        payload = _approval_summary(approval)
        if args.verbose:
            payload["binding"] = redact_json(approval.to_execution_payload())
        _print_payload(payload, as_json=args.json)
        return 0

    print(f"proposal not found: {args.proposal_id}", file=sys.stderr)
    return 2


def broker_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the VMGA broker service")
    parser.add_argument("--host", default="127.0.0.1", help="Broker listen host")
    parser.add_argument("--port", type=int, default=8765, help="Broker listen port")
    parser.add_argument("--policy", default="policies/draft_assist.yaml", help="VMGA policy YAML")
    parser.add_argument("--state-db", default=".vmga/state.sqlite3", help="SQLite state database path")
    parser.add_argument("--ledger", default=".vmga/evidence.jsonl", help="Append-only JSONL ledger path")
    parser.add_argument("--ledger-rotate-bytes", type=int, default=0, help="Rotate ledger before it exceeds this size; 0 disables internal rotation")
    parser.add_argument("--ledger-backups", type=int, default=5, help="Number of rotated ledger files to keep")
    parser.add_argument("--backend", choices=["fake", "gogcli"], default="fake", help="Mailbox backend")
    parser.add_argument("--approval-secret-env", default="VMGA_APPROVAL_SECRET", help="Env var containing approval HMAC secret")
    parser.add_argument("--bearer-token-env", default="VMGA_BROKER_TOKEN", help="Optional env var containing broker bearer token")
    parser.add_argument("--allow-unauthenticated", action="store_true", help="Allow unauthenticated broker access for loopback-only development")
    parser.add_argument("--gog-binary", default="", help="Path to gog-agent-safe or gog")
    parser.add_argument("--gog-account", default=None, help="gog account email")
    parser.add_argument("--gog-client", default=None, help="gog OAuth client name")
    parser.add_argument("--gog-home", default=None, help="gog config root outside the agent workspace")
    parser.add_argument("--gog-timeout", type=float, default=30.0, help="gog command timeout in seconds")
    args = parser.parse_args(argv)

    approval_secret = os.getenv(args.approval_secret_env)
    if not approval_secret:
        print(f"{args.approval_secret_env} is required", file=sys.stderr)
        return 2

    policy = load_vmga_policy(args.policy)
    ledger = JSONLVMGALedger(Path(args.ledger), rotate_bytes=args.ledger_rotate_bytes, backup_count=args.ledger_backups)
    adapter = VMGAGmailAdapter(
        vesta_adapter=LedgerVestaAdapter(ledger),
        profile=str(policy.get("profile", "vmga")),
        policy_rules=policy,
        state_store=SQLiteStateStore(args.state_db),
        approval_secret=approval_secret,
        strict_mode=True,
        fail_closed_on_corrupted_state=True,
    )
    backend = _build_backend(args)
    executor = VMGAExecutor(adapter, backend)
    broker = VMGABroker(adapter, executor, backend=backend)
    bearer_token = os.getenv(args.bearer_token_env)
    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    if args.host not in loopback_hosts and not bearer_token:
        print(
            f"Refusing non-loopback bind without {args.bearer_token_env}; set a bearer token or bind to 127.0.0.1",
            file=sys.stderr,
        )
        return 2
    if args.host not in loopback_hosts and args.allow_unauthenticated:
        print("--allow-unauthenticated is only allowed for loopback hosts", file=sys.stderr)
        return 2
    if not bearer_token and not args.allow_unauthenticated:
        print(
            f"Refusing unauthenticated broker start; set {args.bearer_token_env} or pass --allow-unauthenticated for loopback development",
            file=sys.stderr,
        )
        return 2
    server = make_server(args.host, args.port, broker, bearer_token=bearer_token)

    print(
        f"VMGA broker listening on http://{args.host}:{args.port} with {args.backend} backend",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("VMGA broker stopped", file=sys.stderr)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(verify_evidence_main())
