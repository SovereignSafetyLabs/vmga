"""Opt-in live VMGA broker smoke test implementation."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

from .redaction import dumps_redacted, redact_json
from .vmga_adapter import VMGAGmailAdapter


DEFAULT_OUT = Path("artifacts") / "vmga-live-smoke" / "transcript.redacted.jsonl"


def _approval_token(secret: str, proposal_id: str, proposal_hash: str, approver_id: str) -> str:
    time_window = VMGAGmailAdapter.approval_time_window(datetime.now(timezone.utc))
    message = f"{proposal_id}:{proposal_hash}:{approver_id}:{time_window}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _post_json(broker_url: str, path: str, payload: dict[str, Any], *, token: str | None = None, timeout: float = 10.0) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(
        broker_url.rstrip("/") + path,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return json.loads(body)


def _get_json(broker_url: str, path: str, *, token: str | None = None, timeout: float = 10.0) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(broker_url.rstrip("/") + path, method="GET", headers=headers)
    with request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return json.loads(body)


class Transcript:
    def __init__(self, path: Path, redactions: list[str]):
        self.path = path
        self.redactions = redactions
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def append(self, name: str, payload: dict[str, Any]) -> None:
        event = {
            "name": name,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "payload": redact_json(payload, self.redactions),
        }
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def run_live_smoke(args: argparse.Namespace) -> int:
    redactions = [args.safe_recipient or "", args.draft_body or "", args.broker_token or ""]
    transcript = Transcript(args.out, redactions)
    run_id = getattr(args, "run_id", "") or str(uuid.uuid4())
    send_denial_actor_id = f"{args.actor_id}-send-denial-{run_id[:12]}"
    smoke_metadata = {"source": "vmga_live_smoke", "run_id": run_id}

    try:
        health = _get_json(args.broker_url, "/health", token=args.broker_token, timeout=args.timeout)
        transcript.append("broker_health", health)

        search = _post_json(
            args.broker_url,
            "/v1/proposals",
            {
                "action": "read",
                "actor_id": args.actor_id,
                "search_query": args.search_query,
                "max_results": args.max_results,
                "metadata": smoke_metadata,
            },
            token=args.broker_token,
            timeout=args.timeout,
        )
        transcript.append("search", search)
        if search.get("status") not in {"ALLOW", "OK"}:
            print("search smoke did not allow read/search", file=sys.stderr)
            return 2

        send_denial = _post_json(
            args.broker_url,
            "/v1/proposals",
            {
                "action": "send",
                "actor_id": send_denial_actor_id,
                "recipients": [args.safe_recipient or "nobody@example.invalid"],
                "content": "VMGA smoke send-denial probe. This should not send.",
                "justification": "Verify send remains denied during VMGA live smoke.",
                "metadata": smoke_metadata,
            },
            token=args.broker_token,
            timeout=args.timeout,
        )
        transcript.append("send_denial", send_denial)
        if send_denial.get("status") not in {"DENY", "LOCKDOWN"}:
            print("send denial probe was not denied", file=sys.stderr)
            return 2

        if not args.create_draft:
            return 0

        if not args.safe_recipient:
            print("--safe-recipient is required with --create-draft", file=sys.stderr)
            return 2
        approval_secret = os.getenv(args.approval_secret_env)
        if not approval_secret:
            print("approval HMAC secret is required with --create-draft", file=sys.stderr)
            return 2

        draft = _post_json(
            args.broker_url,
            "/v1/proposals",
            {
                "action": "create_draft",
                "actor_id": args.actor_id,
                "recipients": [args.safe_recipient],
                "subject": f"{args.draft_tag} {args.draft_subject}".strip(),
                "content": f"{args.draft_body}\n\n{args.draft_tag} safe-to-delete smoke draft",
                "justification": "Verify approved draft creation through VMGA live smoke.",
                "metadata": smoke_metadata,
            },
            token=args.broker_token,
            timeout=args.timeout,
        )
        transcript.append("draft_proposal", draft)
        if draft.get("status") != "REVIEW_REQUIRED":
            print("draft proposal did not require review", file=sys.stderr)
            return 2

        approval_token = _approval_token(approval_secret, draft["proposal_id"], draft["proposal_hash"], args.approver_id)
        approval = _post_json(
            args.broker_url,
            "/v1/approvals",
            {
                "proposal_id": draft["proposal_id"],
                "approver_id": args.approver_id,
                "approval_token": approval_token,
            },
            token=args.broker_token,
            timeout=args.timeout,
        )
        transcript.append("draft_approval", approval)
        if approval.get("status") != "APPROVED":
            print("draft approval failed", file=sys.stderr)
            return 2

        execution = _post_json(
            args.broker_url,
            "/v1/executions",
            {
                "proposal_id": draft["proposal_id"],
                "proposal_hash": draft["proposal_hash"],
                "approval_token": approval_token,
            },
            token=args.broker_token,
            timeout=args.timeout,
        )
        transcript.append("draft_execution", execution)
        if execution.get("status") != "SUCCESS":
            print("draft execution failed", file=sys.stderr)
            return 2
        return 0
    except error.URLError as exc:
        transcript.append("broker_error", {"error": str(exc)})
        print(f"broker request failed: {exc}", file=sys.stderr)
        return 2
    except (KeyError, ValueError, TypeError) as exc:
        transcript.append("smoke_error", {"error": str(exc)})
        print(f"live smoke failed: {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an opt-in live VMGA broker smoke test")
    parser.add_argument("--live", action="store_true", help="Required safety flag for live broker/account checks")
    parser.add_argument("--broker-url", default=os.getenv("VMGA_BROKER_URL", "http://127.0.0.1:8765"))
    parser.add_argument("--broker-token", default=os.getenv("VMGA_BROKER_TOKEN"))
    parser.add_argument("--actor-id", default="vmga-live-smoke")
    parser.add_argument("--run-id", default="", help="Optional smoke run id; defaults to a random UUID")
    parser.add_argument("--approver-id", default="operator")
    parser.add_argument("--approval-secret-env", default="VMGA_APPROVAL_SECRET")
    parser.add_argument("--search-query", default="in:inbox")
    parser.add_argument("--max-results", type=int, default=1)
    parser.add_argument("--create-draft", action="store_true", help="Create a real Gmail draft after VMGA approval")
    parser.add_argument("--safe-recipient", default=os.getenv("VMGA_SMOKE_SAFE_RECIPIENT", ""))
    parser.add_argument("--draft-tag", default="[VMGA-SMOKE]")
    parser.add_argument("--draft-subject", default="VMGA live smoke draft")
    parser.add_argument("--draft-body", default="This VMGA live smoke draft was created but not sent.")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    if not args.live:
        print("--live is required; this command can touch a real broker/account", file=sys.stderr)
        return 2
    result = run_live_smoke(args)
    print(dumps_redacted({"transcript": str(args.out), "exit_code": result}, [args.safe_recipient, args.broker_token or ""]))
    return result
