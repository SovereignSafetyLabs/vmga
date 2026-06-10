import json
import sqlite3
import tempfile
import threading
import time
from urllib import request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vmga import (
    ApprovalRecord,
    FakeGmailBackend,
    GmailAction,
    SQLiteStateStore,
    VMGABroker,
    VMGAExecutor,
    VMGAGmailAdapter,
    VMGAProposal,
)
from vmga.broker import make_server
from vmga.approvals import approval_contract, validate_approval_dict
from vmga.evidence import evidence_event, verify_events
from vmga.ledger import JSONLVMGALedger, LedgerVestaAdapter
from vmga.posture import PostureConfig
from vmga.proposals import proposal_contract, validate_proposal_dict
from vmga.cli import approval_token_main


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
        policy_rules={"allowed_actions": ["read", "create_draft"], "kinetic_requires_approval": True},
        state_store=state_store,
        approval_secret="test_secret",
    )


def test_versioned_proposal_contract_round_trip():
    proposal = VMGAProposal(
        proposal_id="prop_1",
        action=GmailAction.CREATE_DRAFT,
        actor_id="agent_1",
        recipients=["z@example.com", "a@example.com"],
        requested_at="2026-06-09T00:00:00+00:00",
    )
    contract = proposal_contract(proposal)
    assert contract["schema_version"] == "0.1"
    rebuilt = validate_proposal_dict(contract)
    assert rebuilt.compute_hash() == proposal.compute_hash()


def test_validate_proposal_rejects_missing_fields():
    with pytest.raises(ValueError, match="Missing VMGA proposal field"):
        validate_proposal_dict({"action": "read"})


def test_approval_contract_round_trip():
    approval = ApprovalRecord(
        proposal_id="prop_1",
        proposal_hash="sha256:" + "a" * 64,
        approver_id="operator_1",
        approved_at="2026-06-09T00:00:00+00:00",
        expires_at="2026-06-09T01:00:00+00:00",
    )
    contract = approval_contract(approval)
    assert contract["schema_version"] == "0.1"
    assert validate_approval_dict(contract).proposal_id == "prop_1"


def test_sqlite_state_persists_approval_used_flag():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        adapter = make_adapter(SQLiteStateStore(db_path))
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        assert adapter.approve_proposal(result["proposal_id"], "operator_1", token)["status"] == "APPROVED"
        exec_result = adapter.execute_approved(result["proposal_id"], result["proposal_hash"], token, lambda request: {"ok": True})
        assert exec_result["status"] == "SUCCESS"

        restarted = make_adapter(SQLiteStateStore(db_path))
        replay = restarted.execute_approved(result["proposal_id"], result["proposal_hash"], token, lambda request: {"ok": True})
        assert replay["status"] == "DENY"
        assert replay["error_code"] == "vmga_approval_already_used"


def test_sqlite_state_uses_wal_and_busy_timeout():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        SQLiteStateStore(db_path)
        with sqlite3.connect(db_path) as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000


def test_fake_backend_records_executor_operation():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        backend = FakeGmailBackend()
        executor = VMGAExecutor(adapter, backend)
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        adapter.approve_proposal(result["proposal_id"], "operator_1", token)
        exec_result = executor.execute_approved(result["proposal_id"], result["proposal_hash"], token)
        assert exec_result["status"] == "SUCCESS"
        assert backend.operations[0]["action"] == "create_draft"


def test_broker_propose_and_execute_fail_closed_without_executor():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        broker = VMGABroker(adapter)
        assert broker.health()["status"] == "ok"
        bad = broker.propose({"action": "create_draft"})
        assert bad["status"] == "DENY"
        assert bad["error_code"] == "vmga_broker_bad_request"
        unknown = broker.propose({"action": "read", "actor_id": "agent_1", "surprise": True})
        assert unknown["status"] == "DENY"
        assert unknown["error_code"] == "vmga_broker_bad_request"
        denied = broker.execute({"proposal_id": "p", "proposal_hash": "h", "approval_token": "t"})
        assert denied["error_code"] == "vmga_executor_unavailable"


def test_broker_reports_runtime_posture():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        broker = VMGABroker(
            adapter,
            posture_config=PostureConfig(
                backend="fake",
                policy_path=str(Path(tmpdir) / "policy.yaml"),
                state_db_path=str(Path(tmpdir) / "state.sqlite3"),
                ledger_path=str(Path(tmpdir) / "evidence.jsonl"),
                agent_roots=[str(Path.cwd())],
                allow_unauthenticated=True,
            ),
        )

        posture = broker.posture()
        assert posture["hard_enforcement_ready"] is False
        assert posture["mode"] in {"advisory", "cannot_determine"}
        assert any(check["id"] == "approval_boundary" and check["status"] == "warn" for check in posture["checks"])
        assert broker.health()["posture_mode"] == posture["mode"]


def test_http_broker_exposes_posture_endpoint():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        broker = VMGABroker(
            adapter,
            posture_config=PostureConfig(
                backend="fake",
                state_db_path=str(Path(tmpdir) / "state.sqlite3"),
                ledger_path=str(Path(tmpdir) / "evidence.jsonl"),
                agent_roots=[str(Path.cwd())],
            ),
        )
        server = make_server("127.0.0.1", 0, broker)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            with request.urlopen(f"http://{host}:{port}/v1/posture", timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    assert payload["hard_enforcement_ready"] is False
    assert any(check["id"] == "direct_gmail_bypass" and check["status"] == "unknown" for check in payload["checks"])


def test_broker_executes_allowed_search_through_backend():
    class SearchBackend:
        def __init__(self):
            self.query = None
            self.max_results = None

        def search(self, query, max_results=10):
            self.query = query
            self.max_results = max_results
            return {"status": "SUCCESS", "messages": [{"message_id": "m1"}]}

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        backend = SearchBackend()
        broker = VMGABroker(adapter, backend=backend)

        result = broker.propose(
            {
                "action": "read",
                "actor_id": "agent_1",
                "search_query": "from:test@example.com",
                "max_results": 2,
            }
        )

        assert result["status"] == "ALLOW"
        assert result["backend_result"]["status"] == "SUCCESS"
        assert backend.query == "from:test@example.com"
        assert backend.max_results == 2


def test_broker_executes_allowed_search_through_shipped_fake_backend():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        backend = FakeGmailBackend(
            messages={
                "m1": {"subject": "invoice one", "body": "match"},
                "m2": {"subject": "invoice two", "body": "match"},
            }
        )
        broker = VMGABroker(adapter, backend=backend)

        result = broker.propose(
            {
                "action": "read",
                "actor_id": "agent_1",
                "search_query": "invoice",
                "max_results": 1,
            }
        )

        assert result["status"] == "ALLOW"
        assert result["backend_result"]["backend"] == "fake"
        assert len(result["backend_result"]["messages"]) == 1


def test_broker_injects_correlation_id_into_results_and_evidence():
    with tempfile.TemporaryDirectory() as tmpdir:
        vesta = MockVesta()
        adapter = VMGAGmailAdapter(
            vesta_adapter=vesta,
            profile="draft_assist",
            policy_rules={
                "allowed_actions": ["read", "create_draft"],
                "kinetic_requires_approval": True,
                "draft_policy": {"allow_external_recipients": True, "require_justification": True},
            },
            state_store=SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")),
            approval_secret="test_secret",
        )
        broker = VMGABroker(adapter)

        result = broker.propose(
            {
                "action": "create_draft",
                "actor_id": "agent_1",
                "recipients": ["ops@example.com"],
                "content": "Draft",
                "justification": "Test",
                "correlation_id": "trace-1",
            }
        )

        assert result["status"] == "REVIEW_REQUIRED"
        assert result["correlation_id"] == "trace-1"
        events = vesta.audit_ledger.events
        assert any(event["event_type"] == "vmga_state_saved" and event["correlation_id"] == "trace-1" for event in events)
        assert any(event["event_type"] == "vmga_proposal_received" and event["correlation_id"] == "trace-1" for event in events)


def test_broker_allows_hermes_style_search_without_sender():
    class SearchBackend:
        def search(self, query, max_results=10):
            return {"status": "SUCCESS", "messages": [{"message_id": "m1"}]}

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = VMGAGmailAdapter(
            vesta_adapter=MockVesta(),
            profile="draft_assist",
            policy_rules={
                "allowed_actions": ["read", "create_draft"],
                "kinetic_requires_approval": True,
                "content_analysis": {"enforce_risk_threshold": True, "max_risk_score_auto_allow": 0},
            },
            state_store=SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")),
            approval_secret="test_secret",
        )
        broker = VMGABroker(adapter, backend=SearchBackend())

        result = broker.propose(
            {
                "action": "read",
                "actor_id": "hermes-actor",
                "search_query": "in:inbox",
                "max_results": 1,
            }
        )

        assert result["status"] == "ALLOW"
        assert result["risk_flags"] == ["unknown_sender"]
        assert result["backend_result"]["status"] == "SUCCESS"


def test_evidence_verifier_accepts_valid_sequence_and_rejects_token_leak():
    proposal_hash = "sha256:" + "a" * 64
    events = [
        evidence_event("vmga_proposal_received", proposal_id="p1", proposal_hash=proposal_hash, policy_state="REVIEW_REQUIRED"),
        evidence_event("vmga_proposal_approved", proposal_id="p1", proposal_hash=proposal_hash, approval_token_hash="abc"),
        evidence_event("vmga_action_executed", proposal_id="p1", proposal_hash=proposal_hash),
    ]
    assert verify_events(events).valid

    leaked = events + [evidence_event("vmga_proposal_approved", proposal_id="p2", approval_token="raw")]
    result = verify_events(leaked)
    assert not result.valid
    assert "raw approval_token leaked" in result.errors[0]


def test_jsonl_ledger_and_cli_verifier_shape(tmp_path):
    ledger_path = tmp_path / "evidence.jsonl"
    ledger = JSONLVMGALedger(ledger_path)
    ledger.append(evidence_event("vmga_proposal_received", proposal_id="p1", policy_state="DENY", error_code="vmga_test"))
    assert ledger.read_all()[0]["proposal_id"] == "p1"


def test_jsonl_ledger_rotates_before_disk_growth(tmp_path):
    ledger_path = tmp_path / "evidence.jsonl"
    ledger = JSONLVMGALedger(ledger_path, rotate_bytes=80, backup_count=2)

    ledger.append(evidence_event("vmga_proposal_received", proposal_id="p1", policy_state="ALLOW"))
    ledger.append(evidence_event("vmga_proposal_received", proposal_id="p2", policy_state="ALLOW"))

    assert ledger_path.exists()
    assert (tmp_path / "evidence.jsonl.1").exists()


def test_approval_single_use_is_locked_for_concurrent_execution():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        adapter.approve_proposal(result["proposal_id"], "operator_1", token)

        outputs = []
        output_lock = threading.Lock()
        execution_count = 0

        def handler(_request):
            nonlocal execution_count
            execution_count += 1
            time.sleep(0.05)
            return {"ok": True}

        def execute_once():
            outcome = adapter.execute_approved(result["proposal_id"], result["proposal_hash"], token, handler)
            with output_lock:
                outputs.append(outcome)

        threads = [threading.Thread(target=execute_once), threading.Thread(target=execute_once)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)

        statuses = sorted(output["status"] for output in outputs)
        assert statuses == ["DENY", "SUCCESS"]
        assert execution_count == 1
        assert sum(1 for output in outputs if output.get("error_code") == "vmga_approval_already_used") == 1


def test_approval_mutation_is_locked_for_concurrent_approval():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        outputs = []
        output_lock = threading.Lock()

        def approve_once():
            outcome = adapter.approve_proposal(result["proposal_id"], "operator_1", token)
            with output_lock:
                outputs.append(outcome)

        threads = [threading.Thread(target=approve_once), threading.Thread(target=approve_once)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)

        statuses = sorted(output["status"] for output in outputs)
        assert statuses == ["APPROVED", "ERROR"]
        assert sum(1 for output in outputs if output.get("error_code") == "vmga_proposal_not_found") == 1


def test_proposal_evidence_redacts_and_caps_agent_text():
    with tempfile.TemporaryDirectory() as tmpdir:
        vesta = MockVesta()
        adapter = VMGAGmailAdapter(
            vesta_adapter=vesta,
            profile="draft_assist",
            policy_rules={"allowed_actions": ["read"], "kinetic_requires_approval": True},
            state_store=SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")),
            approval_secret="test_secret",
        )
        secret = "ya29." + "a" * 24
        adapter.propose_action(
            "create_draft",
            "agent_1",
            content="Draft",
            justification=f"{secret} " + "x" * 2000,
        )

        event = next(event for event in vesta.audit_ledger.events if event["event_type"] == "vmga_proposal_received")
        assert secret not in event["justification"]
        assert "[REDACTED]" in event["justification"]
        assert len(event["justification"]) == 1000


def test_reset_lockdown_persists_state():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        adapter = make_adapter(SQLiteStateStore(db_path))
        adapter.lockdown_active = True
        adapter.denial_counts = {"agent_1": 9}

        result = adapter.reset_lockdown("admin_1")

        assert result["status"] == "RESET"
        restarted = make_adapter(SQLiteStateStore(db_path))
        assert restarted.lockdown_active is False
        assert restarted.denial_counts == {}


def test_sqlite_rate_limit_state_expires_stale_attempts():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3"))
        stale = datetime.now(timezone.utc) - timedelta(seconds=7200)
        fresh = datetime.now(timezone.utc)
        store.save_rate_limit_state(
            {
                "stale": {"count": 5, "first_attempt": stale.isoformat()},
                "fresh": {"count": 1, "first_attempt": fresh.isoformat()},
            }
        )

        loaded = store.load_rate_limit_state(lockout_duration_seconds=3600)

        assert sorted(loaded) == ["fresh"]


def test_approval_token_cli_matches_adapter(monkeypatch, capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        expected = adapter.compute_approval_token(
            "proposal_1",
            "sha256:" + "a" * 64,
            "operator_1",
            time_window="2026-06-10-04",
        )
        monkeypatch.setenv("VMGA_APPROVAL_SECRET", "test_secret")

        exit_code = approval_token_main([
            "proposal_1",
            "sha256:" + "a" * 64,
            "operator_1",
            "--time-window",
            "2026-06-10-04",
        ])

        assert exit_code == 0
        assert capsys.readouterr().out.strip() == expected


def test_approval_time_window_uses_five_minute_buckets():
    now = datetime(2026, 6, 10, 4, 17, 30, tzinfo=timezone.utc)

    assert VMGAGmailAdapter.approval_time_window(now) == "2026-06-10-04-15"
