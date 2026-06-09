"""Minimal VMGA broker service and optional HTTP wrapper."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .executor import VMGAExecutor
from .vmga_adapter import VMGAGmailAdapter


class VMGABroker:
    def __init__(self, adapter: VMGAGmailAdapter, executor: Optional[VMGAExecutor] = None):
        self.adapter = adapter
        self.executor = executor

    def health(self) -> Dict[str, Any]:
        return {
            "status": "ok" if not self.adapter.lockdown_active else "lockdown",
            "lockdown_active": self.adapter.lockdown_active,
            "profile": self.adapter.profile,
        }

    def propose(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {
            "action", "actor_id", "thread_id", "message_ids", "content",
            "recipients", "attachment_ids", "justification", "sender",
        }
        kwargs = {key: value for key, value in payload.items() if key in allowed}
        if "action" not in kwargs or "actor_id" not in kwargs:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": "action and actor_id are required"}
        return self.adapter.propose_action(**kwargs)

    def approve(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self.adapter.approve_proposal(
                proposal_id=payload["proposal_id"],
                approver_id=payload["approver_id"],
                approval_token=payload["approval_token"],
            )
        except KeyError as exc:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": f"missing {exc.args[0]}"}

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.executor is None:
            return {"status": "DENY", "error_code": "vmga_executor_unavailable", "error": "executor unavailable"}
        try:
            return self.executor.execute_approved(
                proposal_id=payload["proposal_id"],
                proposal_hash=payload["proposal_hash"],
                approval_token=payload["approval_token"],
            )
        except KeyError as exc:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": f"missing {exc.args[0]}"}


class VMGAHTTPHandler(BaseHTTPRequestHandler):
    broker: VMGABroker
    bearer_token: Optional[str] = None

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _authorized(self) -> bool:
        if not self.bearer_token:
            return True
        return self.headers.get("Authorization") == f"Bearer {self.bearer_token}"

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"status": "DENY", "error_code": "vmga_broker_unauthorized"})
            return
        if self.path == "/health":
            self._send(200, self.broker.health())
            return
        self._send(404, {"status": "ERROR", "error_code": "vmga_broker_not_found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"status": "DENY", "error_code": "vmga_broker_unauthorized"})
            return
        payload = self._read_json()
        routes = {
            "/propose": self.broker.propose,
            "/v1/proposals": self.broker.propose,
            "/approve": self.broker.approve,
            "/v1/approvals": self.broker.approve,
            "/execute": self.broker.execute,
            "/v1/executions": self.broker.execute,
        }
        handler = routes.get(self.path)
        if handler is None:
            self._send(404, {"status": "ERROR", "error_code": "vmga_broker_not_found"})
            return
        self._send(200, handler(payload))


def make_server(host: str, port: int, broker: VMGABroker, bearer_token: Optional[str] = None) -> ThreadingHTTPServer:
    class Handler(VMGAHTTPHandler):
        pass

    Handler.broker = broker
    Handler.bearer_token = bearer_token
    return ThreadingHTTPServer((host, port), Handler)
