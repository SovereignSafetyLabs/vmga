from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from vmga import SQLiteStateStore, VMGAGmailAdapter
from vmga.cli import broker_main, operator_main


class MockLedger:
    def append(self, event):
        return None


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


def _make_state_with_pending() -> tuple[tempfile.TemporaryDirectory, str, dict]:
    tmp = tempfile.TemporaryDirectory()
    state_db = str(Path(tmp.name) / "state.sqlite3")
    adapter = VMGAGmailAdapter(
        vesta_adapter=MockVesta(),
        profile="draft_assist",
        policy_rules={
            "allowed_actions": ["read", "create_draft"],
            "kinetic_requires_approval": True,
            "draft_policy": {"allow_external_recipients": True, "require_justification": True},
        },
        state_store=SQLiteStateStore(state_db),
        approval_secret="secret",
    )
    proposal = adapter.propose_action(
        "create_draft",
        "agent_1",
        recipients=["ops@example.com"],
        content="sensitive body",
        justification="test",
    )
    return tmp, state_db, proposal


def test_operator_list_shows_safe_pending_summary(capsys):
    tmp, state_db, proposal = _make_state_with_pending()
    try:
        result = operator_main(["--state-db", state_db, "--json", "list"])
    finally:
        tmp.cleanup()

    assert result == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["kind"] == "pending"
    assert rows[0]["proposal_id"] == proposal["proposal_id"]
    assert rows[0]["recipient_count"] == 1
    assert "sensitive body" not in json.dumps(rows)


def test_operator_show_verbose_redacts_secret_like_content(capsys):
    tmp, state_db, proposal = _make_state_with_pending()
    try:
        result = operator_main(["--state-db", state_db, "--json", "show", proposal["proposal_id"], "--verbose"])
    finally:
        tmp.cleanup()

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["proposal_id"] == proposal["proposal_id"]
    assert payload["binding"]["content"] == "sensitive body"


def test_operator_approve_posts_to_broker_with_bearer_token(monkeypatch, capsys):
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"status":"APPROVED"}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["auth"] = req.headers.get("Authorization")
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setenv("VMGA_BROKER_TOKEN", "broker-token")
    with patch("urllib.request.urlopen", fake_urlopen):
        result = operator_main([
            "--broker-url",
            "https://vmga.example.invalid",
            "--json",
            "approve",
            "p1",
            "operator",
            "token",
        ])

    assert result == 0
    assert captured["url"] == "https://vmga.example.invalid/v1/approvals"
    assert captured["auth"] == "Bearer broker-token"
    assert captured["payload"]["proposal_id"] == "p1"
    assert json.loads(capsys.readouterr().out)["status"] == "APPROVED"


def test_operator_posture_queries_broker_with_bearer_token(monkeypatch, capsys):
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"mode":"advisory","checks":[]}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["auth"] = req.headers.get("Authorization")
        return FakeResponse()

    monkeypatch.setenv("VMGA_BROKER_TOKEN", "broker-token")
    with patch("urllib.request.urlopen", fake_urlopen):
        result = operator_main([
            "--broker-url",
            "https://vmga.example.invalid",
            "--json",
            "posture",
        ])

    assert result == 0
    assert captured["url"] == "https://vmga.example.invalid/v1/posture"
    assert captured["auth"] == "Bearer broker-token"
    assert json.loads(capsys.readouterr().out)["mode"] == "advisory"


def test_operator_posture_local_marks_repo_paths_advisory(capsys):
    result = operator_main([
        "--json",
        "--state-db",
        ".vmga/state.sqlite3",
        "posture",
        "--local",
        "--ledger",
        ".vmga/evidence.jsonl",
        "--agent-root",
        str(Path.cwd()),
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hard_enforcement_ready"] is False
    assert any(check["id"] == "state_path" and check["status"] == "warn" for check in payload["checks"])


def test_operator_posture_local_paths_unknown_without_agent_root(capsys):
    result = operator_main([
        "--json",
        "--state-db",
        ".vmga/state.sqlite3",
        "posture",
        "--local",
        "--ledger",
        ".vmga/evidence.jsonl",
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(check["id"] == "state_path" and check["status"] == "unknown" for check in payload["checks"])


def test_broker_main_refuses_non_loopback_without_bearer_token(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "secret")
    monkeypatch.delenv("VMGA_BROKER_TOKEN", raising=False)

    result = broker_main(
        [
            "--host",
            "0.0.0.0",
            "--policy",
            "policies/draft_assist.yaml",
            "--state-db",
            str(tmp_path / "state.sqlite3"),
            "--ledger",
            str(tmp_path / "evidence.jsonl"),
        ]
    )

    assert result == 2
    assert "Refusing non-loopback bind without VMGA_BROKER_TOKEN" in capsys.readouterr().err


def test_broker_main_requires_explicit_loopback_unauthenticated_opt_in(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "secret")
    monkeypatch.delenv("VMGA_BROKER_TOKEN", raising=False)

    result = broker_main(
        [
            "--policy",
            "policies/draft_assist.yaml",
            "--state-db",
            str(tmp_path / "state.sqlite3"),
            "--ledger",
            str(tmp_path / "evidence.jsonl"),
        ]
    )

    assert result == 2
    assert "Refusing unauthenticated broker start" in capsys.readouterr().err


def test_broker_main_allows_explicit_loopback_unauthenticated_dev(monkeypatch, tmp_path):
    class FakeServer:
        def serve_forever(self):
            return None

        def server_close(self):
            return None

    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "secret")
    monkeypatch.delenv("VMGA_BROKER_TOKEN", raising=False)
    with patch("vmga.cli.make_server", return_value=FakeServer()) as make_server:
        result = broker_main(
            [
                "--allow-unauthenticated",
                "--policy",
                "policies/draft_assist.yaml",
                "--state-db",
                str(tmp_path / "state.sqlite3"),
                "--ledger",
                str(tmp_path / "evidence.jsonl"),
            ]
        )

    assert result == 0
    assert make_server.call_args.args[0] == "127.0.0.1"
    assert make_server.call_args.kwargs["bearer_token"] is None


def test_broker_main_prints_posture_summary(monkeypatch, tmp_path, capsys):
    class FakeServer:
        def serve_forever(self):
            return None

        def server_close(self):
            return None

    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "secret")
    monkeypatch.setenv("VMGA_BROKER_TOKEN", "broker-token")
    with patch("vmga.cli.make_server", return_value=FakeServer()):
        result = broker_main(
            [
                "--policy",
                "policies/draft_assist.yaml",
                "--state-db",
                str(tmp_path / "state.sqlite3"),
                "--ledger",
                str(tmp_path / "evidence.jsonl"),
            ]
        )

    assert result == 0
    assert "VMGA posture:" in capsys.readouterr().err
