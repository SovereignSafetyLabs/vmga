from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from vmga import GogCLIBackend, SQLiteStateStore, VMGAExecutor, VMGAGmailAdapter


class MockLedger:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


class MockVesta:
    def __init__(self):
        self.audit_ledger = MockLedger()

    def execute(self, request, handler):
        output = handler(request)

        class Result:
            request_id = request.request_id
            duration_ms = 1
            tool_output = output

        return Result()


def make_adapter(state_store):
    return VMGAGmailAdapter(
        vesta_adapter=MockVesta(),
        profile="draft_assist",
        policy_rules={
            "allowed_actions": ["read", "create_draft"],
            "kinetic_requires_approval": True,
            "draft_policy": {"allow_external_recipients": True},
        },
        state_store=state_store,
        approval_secret="test_secret",
    )


def test_gogcli_search_uses_list_command_and_safe_flags():
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"messages":[]}', stderr="")
    with patch("vmga.backends.gogcli.subprocess.run", return_value=completed) as run:
        backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe", account="ops@example.com")
        result = backend.search("from:test@example.com", max_results=3)

    command = run.call_args.args[0]
    assert isinstance(command, list)
    assert "--gmail-no-send" in command
    assert "--no-input" in command
    assert "--enable-commands-exact=gmail.search,gmail.get,gmail.drafts.create" in command
    assert command[-6:] == ["gmail", "search", "--max", "3", "--", "from:test@example.com"]
    assert result["status"] == "SUCCESS"
    assert result["result"] == {"messages": []}


def test_gogcli_create_draft_sends_body_on_stdin_not_command_line():
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"id":"draft_1"}', stderr="")
    with patch("vmga.backends.gogcli.subprocess.run", return_value=completed) as run:
        backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe")
        result = backend.execute(
            "create_draft",
            {
                "recipients": ["ops@example.com"],
                "content": "Bound draft body",
                "parameters": {"subject": "Bound subject"},
            },
        )

    command = run.call_args.args[0]
    assert "--body-file=-" in command
    assert "Bound draft body" not in command
    assert run.call_args.kwargs["input"] == "Bound draft body"
    assert result["status"] == "SUCCESS"


def test_gogcli_isolates_option_like_user_values():
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"messages":[]}', stderr="")
    with patch("vmga.backends.gogcli.subprocess.run", return_value=completed) as run:
        backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe")
        backend.search("--config=/tmp/evil", max_results=1)

    command = run.call_args.args[0]
    assert command[-6:] == ["gmail", "search", "--max", "1", "--", "--config=/tmp/evil"]

    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"id":"draft_1"}', stderr="")
    with patch("vmga.backends.gogcli.subprocess.run", return_value=completed) as run:
        backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe")
        backend.execute(
            "create_draft",
            {
                "recipients": ["ops@example.com"],
                "content": "Body",
                "parameters": {"subject": "--config=/tmp/evil"},
            },
        )

    command = run.call_args.args[0]
    assert "--subject=--config=/tmp/evil" in command
    assert "--config=/tmp/evil" not in command


def test_gogcli_revalidates_direct_backend_payloads():
    backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe")

    comma_recipient = backend.execute(
        "create_draft",
        {
            "recipients": ["ops@example.com,attacker@example.com"],
            "content": "Body",
            "parameters": {"subject": "Safe subject"},
        },
    )
    hidden_subject = backend.execute(
        "create_draft",
        {
            "recipients": ["ops@example.com"],
            "content": "Body",
            "parameters": {"subject": "Safe\u200b subject"},
        },
    )

    assert comma_recipient["status"] == "DENY"
    assert comma_recipient["error_code"] == "vmga_gogcli_invalid_payload"
    assert "bare email address" in comma_recipient["error"]
    assert hidden_subject["status"] == "DENY"
    assert hidden_subject["error_code"] == "vmga_gogcli_invalid_payload"
    assert "control characters" in hidden_subject["error"]


def test_gogcli_denies_send_even_if_called_directly():
    backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe")

    result = backend.execute("send", {"recipients": ["ops@example.com"], "content": "send it"})

    assert result["status"] == "DENY"
    assert result["error_code"] == "vmga_gogcli_action_denied"


def test_gogcli_retries_rate_limits_with_backoff():
    rate_limited = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="HTTP 429 rate limit")
    success = subprocess.CompletedProcess(args=[], returncode=0, stdout='{"messages":[]}', stderr="")
    with patch("vmga.backends.gogcli.subprocess.run", side_effect=[rate_limited, success]) as run:
        with patch("vmga.backends.gogcli.time.sleep") as sleep:
            backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe", backoff_initial_seconds=0.25)
            result = backend.search("in:inbox", max_results=1)

    assert run.call_count == 2
    sleep.assert_called_once_with(0.25)
    assert result["status"] == "SUCCESS"


def test_gogcli_error_output_is_capped_but_hashed():
    stderr = "credential unlock failed " + ("x" * 5000)
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="partial stdout", stderr=stderr)
    with patch("vmga.backends.gogcli.subprocess.run", return_value=completed):
        backend = GogCLIBackend(binary="/opt/homebrew/bin/gog-agent-safe")
        result = backend.search("in:inbox", max_results=1)

    assert result["status"] == "ERROR"
    assert result["stdout"] == "partial stdout"
    assert result["stderr"].endswith("...[truncated]")
    assert len(result["stderr"]) < len(stderr)
    assert result["stdout_full_sha256"]
    assert result["stderr_full_sha256"]


def test_executor_passes_approval_bound_payload_to_backend():
    class CapturingBackend:
        def __init__(self):
            self.payload = None

        def execute(self, action, payload):
            self.payload = payload
            return {"ok": True, "action": action}

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        backend = CapturingBackend()
        executor = VMGAExecutor(adapter, backend)
        proposed = adapter.propose_action(
            "create_draft",
            "agent_1",
            recipients=["ops@example.com"],
            content="Approved body",
            parameters={"subject": "Approved subject"},
            justification="Test",
        )
        token = adapter.compute_approval_token(proposed["proposal_id"], proposed["proposal_hash"], "operator_1")
        adapter.approve_proposal(proposed["proposal_id"], "operator_1", token)

        result = executor.execute_approved(proposed["proposal_id"], proposed["proposal_hash"], token)
        assert result["status"] == "SUCCESS"
        assert result["tool_output"] == {"ok": True, "action": "create_draft"}
        assert backend.payload["content"] == "Approved body"
        assert backend.payload["parameters"]["subject"] == "Approved subject"
        assert backend.payload["recipients"] == ["ops@example.com"]


def test_executor_surfaces_backend_failure_and_consumes_approval():
    class FailingBackend:
        def execute(self, action, payload):
            return {
                "status": "ERROR",
                "backend": "gogcli",
                "error_code": "vmga_gogcli_failed",
                "error": "credential unlock failed",
            }

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        executor = VMGAExecutor(adapter, FailingBackend())
        proposed = adapter.propose_action(
            "create_draft",
            "agent_1",
            recipients=["ops@example.com"],
            content="Approved body",
            parameters={"subject": "Approved subject"},
            justification="Test",
        )
        token = adapter.compute_approval_token(proposed["proposal_id"], proposed["proposal_hash"], "operator_1")
        adapter.approve_proposal(proposed["proposal_id"], "operator_1", token)

        result = executor.execute_approved(proposed["proposal_id"], proposed["proposal_hash"], token)
        replay = executor.execute_approved(proposed["proposal_id"], proposed["proposal_hash"], token)

        assert result["status"] == "ERROR"
        assert result["error_code"] == "vmga_gogcli_failed"
        assert result["error"] == "credential unlock failed"
        assert result["tool_output"]["backend"] == "gogcli"
        assert replay["status"] == "DENY"
        assert replay["error_code"] == "vmga_approval_already_used"
