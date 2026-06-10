"""gogcli-backed Gmail backend for broker-side VMGA execution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


DEFAULT_ALLOWED_COMMANDS = "gmail.search,gmail.get,gmail.drafts.create"


def _cap_text(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


@dataclass
class GogCLIBackend:
    """Run a narrow, no-send gogcli Gmail surface behind VMGA."""

    binary: str = ""
    account: Optional[str] = None
    client: Optional[str] = None
    home: Optional[str] = None
    timeout_seconds: float = 30.0
    gmail_no_send: bool = True
    wrap_untrusted: bool = True
    enable_commands_exact: str = DEFAULT_ALLOWED_COMMANDS

    def __post_init__(self) -> None:
        if self.binary:
            return
        env_binary = os.getenv("VMGA_GOG_BINARY")
        self.binary = env_binary or shutil.which("gog-agent-safe") or shutil.which("gog") or "/opt/homebrew/bin/gog-agent-safe"

    def _base_command(self) -> List[str]:
        command = [
            self.binary,
            "--json",
            "--no-input",
            f"--enable-commands-exact={self.enable_commands_exact}",
        ]
        if self.gmail_no_send:
            command.append("--gmail-no-send")
        if self.wrap_untrusted:
            command.append("--wrap-untrusted")
        if self.home:
            command.extend(["--home", self.home])
        if self.account:
            command.extend(["--account", self.account])
        if self.client:
            command.extend(["--client", self.client])
        return command

    def _run(self, args: List[str], *, input_text: Optional[str] = None) -> Dict[str, Any]:
        command = self._base_command() + args
        try:
            completed = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            return {
                "status": "ERROR",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_not_found",
                "error": f"gog binary not found: {self.binary}",
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "ERROR",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_timeout",
                "error": f"gog command timed out after {self.timeout_seconds} seconds",
            }

        if completed.returncode != 0:
            return {
                "status": "ERROR",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_failed",
                "exit_code": completed.returncode,
                "stdout": _cap_text(completed.stdout.strip()),
                "stderr": _cap_text(completed.stderr.strip()),
            }

        stdout = completed.stdout.strip()
        if not stdout:
            return {"status": "SUCCESS", "backend": "gogcli", "result": None}

        try:
            result: Any = json.loads(stdout)
        except ValueError:
            result = {"raw": _cap_text(stdout)}
        return {"status": "SUCCESS", "backend": "gogcli", "result": result}

    def search(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        query = str(query).strip()
        if not query:
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_query_required"}
        return self._run(["gmail", "search", query, "--max", str(max_results)])

    def read(self, message_id: str) -> Dict[str, Any]:
        message_id = str(message_id).strip()
        if not message_id:
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_message_id_required"}
        return self._run(["gmail", "get", message_id, "--format", "full", "--sanitize-content"])

    def execute(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if action != "create_draft":
            return {
                "status": "DENY",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_action_denied",
                "error": f"gogcli backend does not execute action: {action}",
            }

        parameters = payload.get("parameters") or {}
        recipients = [str(item) for item in payload.get("recipients", []) if str(item).strip()]
        content = payload.get("content")
        subject = str(parameters.get("subject") or "VMGA draft")
        if not recipients:
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_recipients_required"}
        if not isinstance(content, str) or not content.strip():
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_content_required"}

        command = [
            "gmail",
            "drafts",
            "create",
            "--to",
            ",".join(recipients),
            "--subject",
            subject,
            "--body-file",
            "-",
        ]
        if payload.get("thread_id"):
            command.extend(["--thread-id", str(payload["thread_id"])])
        reply_to_message_id = parameters.get("reply_to_message_id")
        if reply_to_message_id:
            command.extend(["--reply-to-message-id", str(reply_to_message_id)])
        return self._run(command, input_text=content)
