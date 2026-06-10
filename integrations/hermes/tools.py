"""Hermes VMGA tool handlers.

All calls go through the VMGA broker and return JSON strings.
Failures return explicit deny payloads (fail-closed).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib import error, request


BROKER_DEFAULT_ENDPOINT = "/v1/proposals"
BROKER_TIMEOUT_SECONDS = 2.5


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    if isinstance(value, (str, int, float)):
        return [str(value)]
    return []


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _denial_json(tool_name: str, error_code: str, detail: str) -> str:
    return json.dumps(
        {
            "status": "DENY",
            "tool": tool_name,
            "error_code": error_code,
            "error": detail,
        },
        sort_keys=True,
    )


def _resolve_broker_url(args: Any, kwargs: Dict[str, Any]) -> str:
    if isinstance(args, dict) and isinstance(args.get("broker_url"), str) and args["broker_url"].strip():
        return args["broker_url"].strip()

    broker_url = kwargs.get("broker_url")
    if isinstance(broker_url, str) and broker_url.strip():
        return broker_url.strip()

    env_broker_url = os.getenv("VMGA_BROKER_URL")
    if isinstance(env_broker_url, str) and env_broker_url.strip():
        return env_broker_url.strip()

    raise RuntimeError("VMGA_BROKER_URL is required")


def _resolve_broker_token(args: Any, kwargs: Dict[str, Any]) -> Optional[str]:
    if isinstance(args, dict) and isinstance(args.get("broker_token"), str) and args["broker_token"].strip():
        return args["broker_token"].strip()
    broker_token = kwargs.get("broker_token")
    if isinstance(broker_token, str) and broker_token.strip():
        return broker_token.strip()
    env_broker_token = os.getenv("VMGA_BROKER_TOKEN")
    if isinstance(env_broker_token, str) and env_broker_token.strip():
        return env_broker_token.strip()
    return None


def _send_to_broker(tool_name: str, payload: Dict[str, Any], args: Any, kwargs: Dict[str, Any]) -> str:
    try:
        broker_url = _resolve_broker_url(args, kwargs)
    except RuntimeError as exc:
        return _denial_json(tool_name, "vmga_broker_missing", str(exc))

    try:
        endpoint = broker_url.rstrip("/") + BROKER_DEFAULT_ENDPOINT
        request_payload = json.dumps(payload, sort_keys=True).encode("utf-8")
        req = request.Request(
            endpoint,
            data=request_payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        broker_token = _resolve_broker_token(args, kwargs)
        if broker_token:
            req.add_header("Authorization", f"Bearer {broker_token}")
        with request.urlopen(req, timeout=BROKER_TIMEOUT_SECONDS) as response:
            body = response.read()
    except error.URLError as exc:
        return _denial_json(tool_name, "vmga_broker_unreachable", str(exc))
    except Exception as exc:
        return _denial_json(tool_name, "vmga_broker_request_failed", str(exc))

    try:
        broker_output = json.loads(body.decode("utf-8"))
    except (TypeError, ValueError) as exc:
        return _denial_json(tool_name, "vmga_broker_bad_json", str(exc))

    return json.dumps({
        "status": "OK",
        "tool": tool_name,
        "broker_response": broker_output,
    }, sort_keys=True)


def _build_payload(action: str, args: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(args, dict):
        raise ValueError("Hermes tool arguments must be a JSON object")

    actor_id = args.get("actor_id") or kwargs.get("actor_id") or "hermes-actor"
    if not isinstance(actor_id, str) or not actor_id.strip():
        actor_id = "hermes-actor"

    return {
        "action": action,
        "actor_id": actor_id,
        "thread_id": args.get("thread_id"),
        "message_ids": _as_list(args.get("message_ids")),
        "subject": args.get("subject"),
        "content": args.get("content"),
        "recipients": _as_list(args.get("recipients")),
        "attachment_ids": _as_list(args.get("attachment_ids")),
        "justification": args.get("justification", ""),
        "requested_at": _now_iso(),
        "metadata": {
            "source": "hermes",
            "session_id": args.get("session_id"),
            "tool_context": args.get("tool_context"),
        },
    }


def _handler(tool_name: str, args: Any, kwargs: Dict[str, Any], *, action: str) -> str:
    try:
        payload = _build_payload(action, args, kwargs)
    except (TypeError, ValueError) as exc:
        return _denial_json(tool_name, "vmga_invalid_payload", str(exc))

    extra_payload: Dict[str, Any] = {**payload}

    if tool_name == "mail_search":
        extra_payload["search_query"] = str(args.get("query", "")).strip()
        if not extra_payload["search_query"]:
            return _denial_json(tool_name, "vmga_invalid_payload", "query is required")
        extra_payload["max_results"] = args.get("max_results", 10)

    elif tool_name == "mail_get":
        message_id = args.get("message_id") if isinstance(args, dict) else None
        if not isinstance(message_id, str) or not message_id.strip():
            return _denial_json(tool_name, "vmga_invalid_payload", "message_id is required")
        extra_payload["message_id"] = message_id

    elif tool_name == "mail_get_attachment":
        if not isinstance(args, dict) or not args.get("message_id"):
            return _denial_json(tool_name, "vmga_invalid_payload", "message_id is required")
        if not args.get("attachment_id"):
            return _denial_json(tool_name, "vmga_invalid_payload", "attachment_id is required")
        extra_payload["message_id"] = str(args.get("message_id"))
        extra_payload["attachment_ids"] = [str(args.get("attachment_id"))]

    if action in {"create_draft", "send"}:
        recipients = _as_list(args.get("recipients"))
        if not recipients:
            return _denial_json(tool_name, "vmga_invalid_payload", "recipients are required")
        if not isinstance(args.get("content"), str) or not str(args["content"]).strip():
            return _denial_json(tool_name, "vmga_invalid_payload", "content is required")
        extra_payload["recipients"] = recipients

    return _send_to_broker(tool_name, extra_payload, args, kwargs)


def mail_search(args: Any, **kwargs) -> str:
    return _handler("mail_search", args, kwargs, action="read")


def mail_get(args: Any, **kwargs) -> str:
    return _handler("mail_get", args, kwargs, action="read")


def mail_get_attachment(args: Any, **kwargs) -> str:
    return _handler("mail_get_attachment", args, kwargs, action="download_attachment")


def mail_create_draft(args: Any, **kwargs) -> str:
    return _handler("mail_create_draft", args, kwargs, action="create_draft")


def mail_send(args: Any, **kwargs) -> str:
    return _handler("mail_send", args, kwargs, action="send")


__all__ = [
    "mail_search",
    "mail_get",
    "mail_get_attachment",
    "mail_create_draft",
    "mail_send",
]
