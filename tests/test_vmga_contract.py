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


def approve_sqlite_draft(db_path: str):
    adapter = make_adapter(SQLiteStateStore(db_path))
    result = adapter.propose_action(
        "create_draft",
        "agent_1",
        content="Draft",
        parameters={"subject": "Approved subject"},
        justification="Test",
    )
    token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
    assert adapter.approve_proposal(result["proposal_id"], "operator_1", token)["status"] == "APPROVED"
    return result, token


def bitflip_hex_digest(value: str) -> str:
    prefix, digest = value.split(":", 1)
    replacement = "0" if digest[-1] != "0" else "1"
    return f"{prefix}:{digest[:-1]}{replacement}"


def mutate_sqlite_approval(db_path: str, proposal_id: str, mutate):
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT payload FROM approvals WHERE proposal_id = ?", (proposal_id,)).fetchone()
        payload = json.loads(row[0])
        mutate(payload)
        conn.execute(
            "UPDATE approvals SET payload = ? WHERE proposal_id = ?",
            (json.dumps(payload, sort_keys=True), proposal_id),
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


def test_sqlite_approval_consumption_is_atomic_across_independent_adapters():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        approver = make_adapter(SQLiteStateStore(db_path))
        result = approver.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = approver.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        assert approver.approve_proposal(result["proposal_id"], "operator_1", token)["status"] == "APPROVED"

        adapter_a = make_adapter(SQLiteStateStore(db_path))
        adapter_b = make_adapter(SQLiteStateStore(db_path))
        release = threading.Event()
        entered = threading.Event()
        execution_count = 0
        execution_lock = threading.Lock()

        def handler(_request):
            nonlocal execution_count
            with execution_lock:
                execution_count += 1
            entered.set()
            release.wait(timeout=5)
            return {"ok": True}

        outcomes = []

        def run(adapter):
            outcomes.append(adapter.execute_approved(result["proposal_id"], result["proposal_hash"], token, handler))

        first = threading.Thread(target=run, args=(adapter_a,))
        second = threading.Thread(target=run, args=(adapter_b,))
        first.start()
        assert entered.wait(timeout=5)
        second.start()
        release.set()
        first.join(timeout=5)
        second.join(timeout=5)

        statuses = sorted(outcome["status"] for outcome in outcomes)
        assert statuses == ["DENY", "SUCCESS"]
        assert execution_count == 1
        assert any(outcome.get("error_code") == "vmga_approval_already_used" for outcome in outcomes)


def test_sqlite_approval_consumed_before_execution_failure_denies_replay_after_restart():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        adapter = make_adapter(SQLiteStateStore(db_path))
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1")
        assert adapter.approve_proposal(result["proposal_id"], "operator_1", token)["status"] == "APPROVED"

        def failing_handler(_request):
            raise RuntimeError("backend unavailable after consume")

        failed = adapter.execute_approved(result["proposal_id"], result["proposal_hash"], token, failing_handler)
        assert failed["status"] == "ERROR"
        assert failed["error_code"] == "vmga_execution_failed"

        restarted = make_adapter(SQLiteStateStore(db_path))
        replay = restarted.execute_approved(result["proposal_id"], result["proposal_hash"], token, lambda request: {"ok": True})
        assert replay["status"] == "DENY"
        assert replay["error_code"] == "vmga_approval_already_used"


@pytest.mark.parametrize(
    ("name", "mutate", "expected_codes"),
    [
        ("proposal_hash_bitflip", lambda p: p.update({"proposal_hash": bitflip_hex_digest(p["proposal_hash"])}), {"vmga_approval_hash_mismatch"}),
        ("approver_id_change", lambda p: p.update({"approver_id": "operator_2"}), {"vmga_approval_binding_mismatch"}),
        ("action_change", lambda p: p.update({"action": "send"}), {"vmga_approval_binding_mismatch"}),
        ("recipients_change", lambda p: p.update({"recipients": ["attacker@example.com"]}), {"vmga_approval_binding_mismatch"}),
        ("content_change", lambda p: p.update({"content": "Changed content"}), {"vmga_approval_binding_mismatch"}),
        ("parameters_change", lambda p: p.update({"parameters": {"subject": "Changed"}}), {"vmga_approval_binding_mismatch"}),
        ("expires_at_change", lambda p: p.update({"expires_at": "2999-01-01T00:00:00+00:00"}), {"vmga_approval_binding_mismatch"}),
        ("blank_binding_hash", lambda p: p.update({"binding_hash": ""}), {"vmga_approval_binding_missing"}),
        ("recipients_type_confusion", lambda p: p.update({"recipients": ["ops@example.com", 7]}), {"vmga_approval_binding_mismatch"}),
        ("message_ids_type_confusion", lambda p: p.update({"message_ids": 7}), {"vmga_approval_binding_mismatch"}),
        ("parameters_type_confusion", lambda p: p.update({"parameters": ["not", "a", "mapping"]}), {"vmga_approval_binding_mismatch"}),
        ("used_string_type_confusion", lambda p: p.update({"used": "false"}), {"vmga_approval_already_used"}),
    ],
)
def test_persisted_approval_mutation_matrix_denies_without_execution(name, mutate, expected_codes):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        result, token = approve_sqlite_draft(db_path)
        mutate_sqlite_approval(db_path, result["proposal_id"], mutate)
        restarted = make_adapter(SQLiteStateStore(db_path))
        execution_count = 0

        def handler(_request):
            nonlocal execution_count
            execution_count += 1
            return {"ok": True}

        outcome = restarted.execute_approved(result["proposal_id"], result["proposal_hash"], token, handler)
        assert outcome["status"] == "DENY", name
        assert outcome["error_code"] in expected_codes
        assert execution_count == 0


@pytest.mark.parametrize(
    ("name", "proposal_hash_mutator", "token_mutator", "expected_codes"),
    [
        ("proposal_hash_bitflip", bitflip_hex_digest, lambda token: token, {"vmga_approval_hash_mismatch"}),
        ("token_bitflip", lambda proposal_hash: proposal_hash, lambda token: token[:-1] + ("0" if token[-1] != "0" else "1"), {"vmga_approval_token_mismatch"}),
    ],
)
def test_execution_request_bitflips_deny_without_execution(name, proposal_hash_mutator, token_mutator, expected_codes):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "vmga.sqlite3")
        result, token = approve_sqlite_draft(db_path)
        restarted = make_adapter(SQLiteStateStore(db_path))
        execution_count = 0

        def handler(_request):
            nonlocal execution_count
            execution_count += 1
            return {"ok": True}

        outcome = restarted.execute_approved(
            result["proposal_id"],
            proposal_hash_mutator(result["proposal_hash"]),
            token_mutator(token),
            handler,
        )

        assert outcome["status"] == "DENY", name
        assert outcome["error_code"] in expected_codes
        assert execution_count == 0


def test_stale_hmac_approval_window_denies_before_approval_record_exists():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        result = adapter.propose_action("create_draft", "agent_1", content="Draft", justification="Test")
        old_window = VMGAGmailAdapter.approval_time_window(datetime.now(timezone.utc) - timedelta(minutes=15))
        stale_token = adapter.compute_approval_token(result["proposal_id"], result["proposal_hash"], "operator_1", old_window)

        approval = adapter.approve_proposal(result["proposal_id"], "operator_1", stale_token)

        assert approval["status"] == "DENY"
        assert approval["error_code"] == "vmga_approval_token_invalid"
        assert result["proposal_id"] not in adapter.approvals


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


def test_posture_path_checks_are_unknown_without_explicit_agent_roots():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        broker = VMGABroker(
            adapter,
            posture_config=PostureConfig(
                backend="gogcli",
                gog_binary="/opt/homebrew/bin/gog-agent-safe",
                policy_path=str(Path(tmpdir) / "policy.yaml"),
                state_db_path=str(Path(tmpdir) / "state.sqlite3"),
                ledger_path=str(Path(tmpdir) / "evidence.jsonl"),
                bearer_token_set=True,
                ledger_rotate_bytes=100,
            ),
        )

        posture = broker.posture()
        assert any(check["id"] == "state_path" and check["status"] == "unknown" for check in posture["checks"])
        assert any(check["id"] == "direct_gmail_bypass" and check["status"] == "unknown" for check in posture["checks"])
        assert posture["mode"] == "cannot_determine"


def test_posture_hard_ready_requires_explicit_bypass_attestation_and_roots(monkeypatch):
    from vmga.evidence import evidence_event
    from vmga.evidence_integrity import EvidenceCheckpoint, add_integrity_metadata, canonical_json_line

    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))

        # Finding 3: declared modes alone no longer reach hard-ready; the
        # signature keyring and evidence chain must be operative.
        key_id = "operator-test"
        key_secret = "contract-test-secret"
        monkeypatch.setenv("VMGA_EVIDENCE_HMAC_KEY", key_secret)
        monkeypatch.setenv("VMGA_EVIDENCE_HMAC_KEY_ID", key_id)
        ledger_path = Path(tmpdir) / "evidence.jsonl"
        record = add_integrity_metadata(
            evidence_event("vmga_proposal_received", proposal_id="p1", policy_state="ALLOW"),
            key_id=key_id, key=key_secret.encode(), sequence=1, prev_mac=None,
        )
        ledger_path.write_text(canonical_json_line(record), encoding="utf-8")
        head_store = SQLiteStateStore(str(Path(tmpdir) / "state.sqlite3"))
        head_store.save_evidence_head(EvidenceCheckpoint(
            ledger_path=str(ledger_path),
            genesis_sequence=1, genesis_mac=record["integrity"]["mac"],
            last_sequence=1, last_mac=record["integrity"]["mac"],
            key_id=key_id,
        ))

        broker = VMGABroker(
            adapter,
            posture_config=PostureConfig(
                backend="gogcli",
                gog_binary="/opt/homebrew/bin/gog-agent-safe",
                policy_path=str(Path(tmpdir) / "policy.yaml"),
                state_db_path=str(Path(tmpdir) / "state.sqlite3"),
                ledger_path=str(ledger_path),
                bearer_token_set=True,
                ledger_rotate_bytes=100,
                approval_auth="signature",
                signature_readiness={"state": "verified_intact", "reason": "active_ed25519_keyring_loaded"},
                evidence_integrity="hmac_chain",
                agent_roots=[str(Path.cwd())],
                gog_home=str(Path(tmpdir) / "gog-home"),
                direct_bypass_attested=True,
                direct_bypass_evidence="artifacts/release/direct-bypass.json",
            ),
        )

        posture = broker.posture()
        assert posture["mode"] == "hard_enforcement_ready"
        assert posture["hard_enforcement_ready"] is True
        assert any(check["id"] == "direct_gmail_bypass" and check["status"] == "pass" for check in posture["checks"])

        # Declared-but-not-operative must NOT be hard-ready.
        broker.posture_config.signature_readiness = None
        assert broker.posture()["hard_enforcement_ready"] is False


def test_http_broker_exposes_posture_endpoint():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = make_adapter(SQLiteStateStore(str(Path(tmpdir) / "vmga.sqlite3")))
        broker = VMGABroker(
            adapter,
            posture_config=PostureConfig(
                backend="fake",
                state_db_path=str(Path(tmpdir) / "state.sqlite3"),
                ledger_path=str(Path(tmpdir) / "evidence.jsonl"),
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


def test_approval_token_cli_missing_secret_does_not_log_env_name(monkeypatch, capsys):
    monkeypatch.delenv("VMGA_APPROVAL_SECRET", raising=False)

    exit_code = approval_token_main([
        "proposal_1",
        "sha256:" + "a" * 64,
        "operator_1",
    ])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "approval HMAC secret is required" in captured.err
    assert "VMGA_APPROVAL_SECRET" not in captured.err


def test_approval_time_window_uses_five_minute_buckets():
    now = datetime(2026, 6, 10, 4, 17, 30, tzinfo=timezone.utc)

    assert VMGAGmailAdapter.approval_time_window(now) == "2026-06-10-04-15"
