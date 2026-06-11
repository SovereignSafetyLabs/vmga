from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vmga import live_smoke as smoke
from vmga.broker_contract import validate_broker_proposal_payload


class _FakeBrokerResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_live_smoke_requires_live_flag(capsys):
    result = smoke.main([])

    captured = capsys.readouterr()
    assert result == 2
    assert "--live is required" in captured.err


def test_live_smoke_search_and_send_denial_are_redacted(tmp_path: Path):
    calls = []
    proposal_payloads = []

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        if req.get_method() == "GET":
            return _FakeBrokerResponse({"status": "ok", "profile": "test"})
        payload = json.loads(req.data.decode("utf-8"))
        proposal_payloads.append(payload)
        if req.full_url.endswith("/v1/proposals"):
            validate_broker_proposal_payload(payload)
        if payload["action"] == "read":
            return _FakeBrokerResponse({"status": "ALLOW", "backend_result": {"status": "SUCCESS"}})
        if payload["action"] == "send":
            return _FakeBrokerResponse({"status": "DENY", "recipient": "person@gmail.com"})
        raise AssertionError(payload)

    out = tmp_path / "transcript.jsonl"
    with patch("vmga.live_smoke.request.urlopen", fake_urlopen):
        result = smoke.main([
            "--live",
            "--broker-url",
            "https://vmga.example.invalid",
            "--safe-recipient",
            "person@gmail.com",
            "--out",
            str(out),
        ])

    assert result == 0
    transcript = out.read_text(encoding="utf-8")
    assert "person@gmail.com" not in transcript
    assert "[REDACTED]" in transcript
    assert len(calls) == 3
    send_payload = next(payload for payload in proposal_payloads if payload["action"] == "send")
    assert send_payload["actor_id"].startswith("vmga-live-smoke-send-denial-")
    assert send_payload["actor_id"] != "vmga-live-smoke-send-denial"
    assert send_payload["metadata"]["run_id"]


def test_live_smoke_send_denial_actor_is_unique_per_run(tmp_path: Path):
    send_actor_ids = []

    def fake_urlopen(req, timeout=None):
        if req.get_method() == "GET":
            return _FakeBrokerResponse({"status": "ok", "profile": "test"})
        payload = json.loads(req.data.decode("utf-8"))
        if payload["action"] == "read":
            return _FakeBrokerResponse({"status": "ALLOW", "backend_result": {"status": "SUCCESS"}})
        if payload["action"] == "send":
            send_actor_ids.append(payload["actor_id"])
            return _FakeBrokerResponse({"status": "DENY"})
        raise AssertionError(payload)

    with patch("vmga.live_smoke.request.urlopen", fake_urlopen):
        first = smoke.main(["--live", "--safe-recipient", "operator@example.com", "--out", str(tmp_path / "one.jsonl")])
        second = smoke.main(["--live", "--safe-recipient", "operator@example.com", "--out", str(tmp_path / "two.jsonl")])

    assert first == 0
    assert second == 0
    assert len(send_actor_ids) == 2
    assert send_actor_ids[0] != send_actor_ids[1]


def test_live_smoke_create_draft_requires_approval_secret(tmp_path: Path, capsys):
    def fake_urlopen(req, timeout=None):
        if req.get_method() == "GET":
            return _FakeBrokerResponse({"status": "ok", "profile": "test"})
        payload = json.loads(req.data.decode("utf-8"))
        if payload["action"] == "read":
            return _FakeBrokerResponse({"status": "ALLOW", "backend_result": {"status": "SUCCESS"}})
        if payload["action"] == "send":
            return _FakeBrokerResponse({"status": "DENY"})
        raise AssertionError(payload)

    args = SimpleNamespace(
        broker_url="https://vmga.example.invalid",
        broker_token=None,
        timeout=1.0,
        out=tmp_path / "transcript.jsonl",
        safe_recipient="operator@example.com",
        draft_body="body",
        draft_tag="[VMGA-SMOKE]",
        search_query="in:inbox",
        max_results=1,
        actor_id="smoke",
        run_id="test-run",
        create_draft=True,
        approval_secret_env="MISSING_VMGA_SECRET",
        approver_id="operator",
        draft_subject="subject",
    )

    with patch.dict(os.environ, {}, clear=False), patch("vmga.live_smoke.request.urlopen", fake_urlopen):
        result = smoke.run_live_smoke(args)

    assert result == 2
    captured = capsys.readouterr()
    assert "approval HMAC secret is required" in captured.err
    assert "MISSING_VMGA_SECRET" not in captured.err
