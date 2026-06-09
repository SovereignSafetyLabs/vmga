"""OpenClaw profile adapter wiring to VMGA broker."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional
from urllib import error
from urllib import request as urllib_request


@dataclass(frozen=True)
class OpenClawRequest:
    tool_id: str
    payload: Mapping[str, Any]
    actor_id: str = "openclaw-operator"
    session_id: str = "openclaw-session"


BROKER_ENDPOINT = "/v1/proposals"

OPENCLAW_TOOL_MAP: Dict[str, str] = {
    "mail_search": "read",
    "mail_get": "read",
    "mail_get_attachment": "download_attachment",
    "mail_create_draft": "create_draft",
    "mail_send": "send",
    "mail_forward": "forward",
    "mail_archive": "archive",
    "mail_delete": "delete",
    "mail_label": "apply_label",
}


DISALLOWED_TOOL_PREFIXES: List[str] = [
    "gmail",
    "gws",
    "gog",
    "workspace",
    "terminal",
    "browser",
    "node.",
]


def _coerce_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float)):
        return [str(value)]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def _is_disallowed_tool(tool_id: str) -> bool:
    tool_norm = tool_id.lower()
    return any(tool_norm == prefix or tool_norm.startswith(prefix) for prefix in DISALLOWED_TOOL_PREFIXES)


def _coerce_recipients(payload: Mapping[str, Any]) -> List[str]:
    return _coerce_string_list(payload.get("recipients"))


def _coerce_message_ids(payload: Mapping[str, Any]) -> List[str]:
    message_ids = _coerce_string_list(payload.get("message_ids"))
    if message_ids:
        return message_ids
    message_id = payload.get("message_id")
    if message_id is not None:
        return [str(message_id)]
    return []


class VMGAOpenClawProfileAdapter:
    """Minimal mapping adapter for OpenClaw tool requests into VMGA proposal calls."""

    def __init__(
        self,
        broker_url: str,
        *,
        timeout_seconds: float = 2.5,
        extra_map: Optional[Mapping[str, str]] = None,
    ):
        self.broker_url = broker_url
        self.timeout_seconds = timeout_seconds
        self.tool_map = dict(OPENCLAW_TOOL_MAP)
        if extra_map:
            for key, value in extra_map.items():
                if isinstance(key, str) and isinstance(value, str):
                    self.tool_map[key] = value

    def map_tool(self, tool_id: str) -> str:
        if tool_id in self.tool_map:
            return self.tool_map[tool_id]
        return "read"

    def build_broker_payload(self, request: OpenClawRequest) -> Dict[str, Any]:
        if _is_disallowed_tool(request.tool_id):
            raise ValueError(f"tool is denied by VMGA static policy: {request.tool_id}")

        action = self.map_tool(request.tool_id)
        payload = {
            "proposal_id": f"openclaw_{request.tool_id}_{request.session_id}",
            "action": action,
            "actor_id": request.actor_id,
            "session_id": request.session_id,
            "thread_id": request.payload.get("thread_id"),
            "message_ids": _coerce_message_ids(request.payload),
            "content": request.payload.get("content"),
            "subject": request.payload.get("subject"),
            "recipients": _coerce_recipients(request.payload),
            "attachment_ids": request.payload.get("attachment_ids", []),
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "source": "openclaw",
                "tool_id": request.tool_id,
            },
        }

        # Ensure deterministic JSON shapes for audit/evidence correlation.
        payload["message_ids"] = [str(value) for value in payload["message_ids"]]
        payload["attachment_ids"] = [str(value) for value in payload["attachment_ids"]]
        return payload

    def execute(self, request_obj: OpenClawRequest) -> Dict[str, Any]:
        try:
            payload = self.build_broker_payload(request_obj)
        except ValueError as exc:
            return {
                "status": "DENY",
                "tool": request_obj.tool_id,
                "error_code": "vmga_tool_denied",
                "error": str(exc),
            }

        try:
            request_payload = json.dumps(payload, sort_keys=True).encode("utf-8")
            req = urllib_request.Request(
                self.broker_url.rstrip("/") + BROKER_ENDPOINT,
                data=request_payload,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            with urllib_request.urlopen(req, timeout=self.timeout_seconds) as response:
                response_json = json.loads(response.read().decode("utf-8"))
            return {
                "status": "OK",
                "tool": request_obj.tool_id,
                "broker_response": response_json,
            }
        except error.URLError as exc:
            return {
                "status": "DENY",
                "tool": request_obj.tool_id,
                "error_code": "vmga_broker_unreachable",
                "error": str(exc),
            }
        except (TypeError, ValueError) as exc:
            return {
                "status": "DENY",
                "tool": request_obj.tool_id,
                "error_code": "vmga_broker_response_invalid",
                "error": str(exc),
            }
        except Exception as exc:
            return {
                "status": "DENY",
                "tool": request_obj.tool_id,
                "error_code": "vmga_adapter_failure",
                "error": str(exc),
            }
