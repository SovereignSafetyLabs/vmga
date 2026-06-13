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
BROKER_CONTEXT_KEYS = {"broker_url", "broker_token"}
ARG_WRAPPER_KEYS = ("arguments", "args", "input", "payload", "tool_input")


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


def _coerce_tool_args(args: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    if args is None:
        tool_args: Dict[str, Any] = {}
    elif isinstance(args, dict):
        tool_args = dict(args)
    else:
        raise ValueError("Hermes tool arguments must be a JSON object")

    for key in ARG_WRAPPER_KEYS:
        wrapped = tool_args.get(key)
        if isinstance(wrapped, dict):
            tool_args = dict(wrapped)
            break

    for key, value in kwargs.items():
        if key not in BROKER_CONTEXT_KEYS and key not in tool_args:
            tool_args[key] = value

    return tool_args


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


def _build_payload(action: str, args: Dict[str, Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
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
        "parameters": args.get("parameters") if isinstance(args.get("parameters"), dict) else {},
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
        tool_args = _coerce_tool_args(args, kwargs)
        payload = _build_payload(action, tool_args, kwargs)
    except (TypeError, ValueError) as exc:
        return _denial_json(tool_name, "vmga_invalid_payload", str(exc))

    extra_payload: Dict[str, Any] = {**payload}

    if tool_name == "mail_search":
        extra_payload["search_query"] = str(tool_args.get("query", "")).strip()
        if not extra_payload["search_query"]:
            return _denial_json(tool_name, "vmga_invalid_payload", "query is required")
        extra_payload["max_results"] = tool_args.get("max_results", 10)

    elif tool_name == "mail_get":
        message_id = tool_args.get("message_id")
        if not isinstance(message_id, str) or not message_id.strip():
            return _denial_json(tool_name, "vmga_invalid_payload", "message_id is required")
        extra_payload["message_id"] = message_id

    elif tool_name == "mail_get_attachment":
        if not tool_args.get("message_id"):
            return _denial_json(tool_name, "vmga_invalid_payload", "message_id is required")
        if not tool_args.get("attachment_id"):
            return _denial_json(tool_name, "vmga_invalid_payload", "attachment_id is required")
        extra_payload["message_id"] = str(tool_args.get("message_id"))
        extra_payload["attachment_ids"] = [str(tool_args.get("attachment_id"))]

    elif tool_name == "mail_archive":
        message_ids = _as_list(tool_args.get("message_ids"))
        if not message_ids and tool_args.get("message_id"):
            message_ids = [str(tool_args["message_id"])]
        if not message_ids:
            return _denial_json(tool_name, "vmga_invalid_payload", "message_id or message_ids is required")
        extra_payload["message_ids"] = message_ids

    elif tool_name == "mail_apply_label":
        message_ids = _as_list(tool_args.get("message_ids"))
        if not message_ids and tool_args.get("message_id"):
            message_ids = [str(tool_args["message_id"])]
        if not message_ids:
            return _denial_json(tool_name, "vmga_invalid_payload", "message_id or message_ids is required")
        label = str(tool_args.get("label", "")).strip()
        if not label:
            return _denial_json(tool_name, "vmga_invalid_payload", "label is required")
        extra_payload["message_ids"] = message_ids
        extra_payload["parameters"] = {**extra_payload["parameters"], "label": label}

    if action in {"create_draft", "send"}:
        recipients = _as_list(tool_args.get("recipients"))
        if not recipients:
            return _denial_json(tool_name, "vmga_invalid_payload", "recipients are required")
        if not isinstance(tool_args.get("content"), str) or not str(tool_args["content"]).strip():
            return _denial_json(tool_name, "vmga_invalid_payload", "content is required")
        extra_payload["recipients"] = recipients

    return _send_to_broker(tool_name, extra_payload, tool_args, kwargs)


def mail_search(args: Any = None, **kwargs) -> str:
    return _handler("mail_search", args, kwargs, action="read")


def mail_get(args: Any = None, **kwargs) -> str:
    return _handler("mail_get", args, kwargs, action="read")


def mail_get_attachment(args: Any = None, **kwargs) -> str:
    return _handler("mail_get_attachment", args, kwargs, action="download_attachment")


def mail_archive(args: Any = None, **kwargs) -> str:
    return _handler("mail_archive", args, kwargs, action="archive")


def mail_apply_label(args: Any = None, **kwargs) -> str:
    return _handler("mail_apply_label", args, kwargs, action="apply_label")


def mail_create_draft(args: Any = None, **kwargs) -> str:
    return _handler("mail_create_draft", args, kwargs, action="create_draft")


def mail_send(args: Any = None, **kwargs) -> str:
    return _handler("mail_send", args, kwargs, action="send")


__all__ = [
    "mail_search",
    "mail_get",
    "mail_get_attachment",
    "mail_archive",
    "mail_apply_label",
    "mail_create_draft",
    "mail_send",
]
