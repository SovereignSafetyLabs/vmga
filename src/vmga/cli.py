"""Command-line helpers for VMGA."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .backends import FakeGmailBackend, GogCLIBackend
from .broker import VMGABroker, make_server
from .evidence import load_jsonl_events, verify_events
from .executor import VMGAExecutor
from .ledger import JSONLVMGALedger, LedgerVestaAdapter
from .sqlite_state import SQLiteStateStore
from .vmga_adapter import VMGAGmailAdapter, load_vmga_policy


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


def broker_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the VMGA broker service")
    parser.add_argument("--host", default="127.0.0.1", help="Broker listen host")
    parser.add_argument("--port", type=int, default=8765, help="Broker listen port")
    parser.add_argument("--policy", default="policies/draft_assist.yaml", help="VMGA policy YAML")
    parser.add_argument("--state-db", default=".vmga/state.sqlite3", help="SQLite state database path")
    parser.add_argument("--ledger", default=".vmga/evidence.jsonl", help="Append-only JSONL ledger path")
    parser.add_argument("--backend", choices=["fake", "gogcli"], default="fake", help="Mailbox backend")
    parser.add_argument("--approval-secret-env", default="VMGA_APPROVAL_SECRET", help="Env var containing approval HMAC secret")
    parser.add_argument("--bearer-token-env", default="VMGA_BROKER_TOKEN", help="Optional env var containing broker bearer token")
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
    ledger = JSONLVMGALedger(Path(args.ledger))
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
