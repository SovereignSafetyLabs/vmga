"""gogcli-backed Gmail backend for broker-side VMGA execution."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..broker_contract import validate_email_list, validate_multiline_text_value, validate_single_line_value


DEFAULT_ALLOWED_COMMANDS = "gmail.search,gmail.get,gmail.drafts.create"


def _cap_text(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


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
    max_retries: int = 2
    backoff_initial_seconds: float = 1.0

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

    @staticmethod
    def _is_rate_limited(stdout: str, stderr: str) -> bool:
        combined = f"{stdout}\n{stderr}".lower()
        return any(token in combined for token in ["rate limit", "ratelimit", "quota", "too many requests", " 429", "429"])

    def _run_once(self, command: List[str], *, input_text: Optional[str] = None) -> subprocess.CompletedProcess[str] | Dict[str, Any]:
        try:
            return subprocess.run(
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

    def _run(self, args: List[str], *, input_text: Optional[str] = None) -> Dict[str, Any]:
        command = self._base_command() + args
        attempts = 0
        completed: subprocess.CompletedProcess[str] | Dict[str, Any]
        while True:
            completed = self._run_once(command, input_text=input_text)
            if isinstance(completed, dict):
                return completed
            if completed.returncode == 0:
                break
            if not self._is_rate_limited(completed.stdout, completed.stderr) or attempts >= self.max_retries:
                break
            delay = self.backoff_initial_seconds * (2 ** attempts)
            time.sleep(delay)
            attempts += 1

        if completed.returncode != 0:
            rate_limited = self._is_rate_limited(completed.stdout, completed.stderr)
            result: Dict[str, Any] = {
                "status": "ERROR",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_rate_limited" if rate_limited else "vmga_gogcli_failed",
                "exit_code": completed.returncode,
                "attempts": attempts + 1,
                "stdout": _cap_text(completed.stdout.strip()),
                "stderr": _cap_text(completed.stderr.strip()),
            }
            if completed.stdout:
                result["stdout_full_sha256"] = _sha256_text(completed.stdout)
            if completed.stderr:
                result["stderr_full_sha256"] = _sha256_text(completed.stderr)
            return result

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
        return self._run(["gmail", "search", "--max", str(max_results), "--", query])

    def read(self, message_id: str) -> Dict[str, Any]:
        message_id = str(message_id).strip()
        if not message_id:
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_message_id_required"}
        return self._run(["gmail", "get", "--format", "full", "--sanitize-content", "--", message_id])

    def execute(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if action != "create_draft":
            return {
                "status": "DENY",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_action_denied",
                "error": f"gogcli backend does not execute action: {action}",
            }

        parameters = payload.get("parameters") or {}
        raw_recipients = payload.get("recipients", [])
        content = payload.get("content")
        subject = str(parameters.get("subject") or "VMGA draft")
        if not raw_recipients:
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_recipients_required"}
        if not isinstance(content, str) or not content.strip():
            return {"status": "DENY", "backend": "gogcli", "error_code": "vmga_gogcli_content_required"}
        try:
            validate_email_list("recipients", raw_recipients)
            validate_single_line_value("parameters.subject", subject)
            validate_multiline_text_value("content", content)
            if payload.get("thread_id"):
                validate_single_line_value("thread_id", payload["thread_id"])
            reply_to_message_id = parameters.get("reply_to_message_id")
            if reply_to_message_id:
                validate_single_line_value("parameters.reply_to_message_id", reply_to_message_id)
        except ValueError as exc:
            return {
                "status": "DENY",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_invalid_payload",
                "error": str(exc),
            }

        recipients = [str(item).strip() for item in raw_recipients]
        command = [
            "gmail",
            "drafts",
            "create",
            f"--to={','.join(recipients)}",
            f"--subject={subject}",
            "--body-file=-",
        ]
        if payload.get("thread_id"):
            command.append(f"--thread-id={payload['thread_id']}")
        if reply_to_message_id:
            command.append(f"--reply-to-message-id={reply_to_message_id}")
        return self._run(command, input_text=content)
