"""Tests for the offline VMGA release check."""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "vmga_release_check.py"
EVIDENCE_SCRIPT_PATH = ROOT / "scripts" / "build_vmga_evidence.py"


def _load_release_checker():
    spec = importlib.util.spec_from_file_location("vmga_release_check", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_evidence_builder():
    spec = importlib.util.spec_from_file_location("build_vmga_evidence", EVIDENCE_SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def _populate_safe_repo(root: Path) -> None:
    _write(root / "LICENSE", "MIT\n")
    _write(root / "README.md", "VMGA does not claim prompt-injection prevention, DLP, host compromise protection, browser/session isolation, compliance certification, or security of Hermes/OpenClaw internals.\n")
    _write(root / "SECURITY.md", "Report security issues here.\n")
    _write(root / "CONTRIBUTING.md", "Contribution guidance.\n")
    _write(root / "docs" / "release_checklist.md", """
        # VMGA Release Checklist

        ## Automated Repo Gates
        Run `scripts/vmga_release_check.py --json`.

        ## Manual Operator Evidence
        Capture deployment evidence.

        ## Runtime Posture Gate
        Capture posture output.

        ## v0.3.0 Gates
        Verify signature and evidence integrity.
    """)
    _write(root / "docs" / "deployment_runbook.md", "Deployment runbook.\n")
    _write(root / "docs" / "openclaw_integration.md", "OpenClaw integration.\n")
    _write(root / "docs" / "hermes_integration.md", "Hermes integration.\n")
    _write(root / "docs" / "dsovs_readiness.md", """
        # DSOVS Readiness Mapping

        This file is not OWASP certification.

        ## Control Mapping
        Evidence map.

        ## Non-Applicable Or Bounded Areas
        Bounded controls.

        ## Gap Handling
        Track repo gaps as issues.
    """)
    _write(root / "docs" / "evidence.md", "VMGA does not claim prompt-injection prevention, DLP, host compromise protection, browser/session isolation, compliance certification, or security of Hermes/OpenClaw internals.\n")
    _write(root / "docs" / "gmail_backend_options.md", "VMGA does not claim prompt-injection prevention, DLP, host compromise protection, browser/session isolation, compliance certification, or security of Hermes/OpenClaw internals.\n")
    _write(root / "docs" / "action_catalog.md", """
        # VMGA Action Catalog

        <!-- BEGIN VMGA_ACTION_CATALOG -->
        ```json
        {
          "schema_version": "vmga-action-catalog-v1",
          "actions": [
            {"action": "read", "class": "non_kinetic", "default_approval": "not_required", "baseline_denies": [], "risk_vectors": ["mailbox_read_access"]},
            {"action": "summarize", "class": "non_kinetic", "default_approval": "not_required", "baseline_denies": [], "risk_vectors": ["mailbox_read_access"]},
            {"action": "classify", "class": "non_kinetic", "default_approval": "not_required", "baseline_denies": [], "risk_vectors": ["mailbox_read_access"]},
            {"action": "extract_entities", "class": "non_kinetic", "default_approval": "not_required", "baseline_denies": [], "risk_vectors": ["metadata_extraction"]},
            {"action": "recommend_draft", "class": "non_kinetic", "default_approval": "not_required", "baseline_denies": [], "risk_vectors": ["suggested_response"]},
            {"action": "create_draft", "class": "kinetic", "default_approval": "required", "baseline_denies": ["credential_transmission"], "risk_vectors": ["draft_creation"]},
            {"action": "send", "class": "kinetic", "default_approval": "required", "baseline_denies": ["bulk_forwarding", "credential_transmission", "financial_instructions", "mfa_recovery_handling"], "risk_vectors": ["mailbox_send"]},
            {"action": "forward", "class": "kinetic", "default_approval": "required", "baseline_denies": ["bulk_forwarding", "credential_transmission", "financial_instructions", "mfa_recovery_handling"], "risk_vectors": ["mailbox_forward"]},
            {"action": "archive", "class": "kinetic", "default_approval": "required", "baseline_denies": [], "risk_vectors": ["mailbox_availability_change"]},
            {"action": "delete", "class": "kinetic", "default_approval": "required", "baseline_denies": [], "risk_vectors": ["mailbox_destruction"]},
            {"action": "apply_label", "class": "kinetic", "default_approval": "required", "baseline_denies": [], "risk_vectors": ["label_abuse"]},
            {"action": "download_attachment", "class": "kinetic", "default_approval": "required", "baseline_denies": [], "risk_vectors": ["attachment_download"]},
            {"action": "mark_read", "class": "kinetic", "default_approval": "required", "baseline_denies": [], "risk_vectors": ["mailbox_visibility_change"]},
            {"action": "move", "class": "kinetic", "default_approval": "required", "baseline_denies": [], "risk_vectors": ["mailbox_availability_change"]}
          ]
        }
        ```
        <!-- END VMGA_ACTION_CATALOG -->
    """)
    _write(root / "policies" / "observe_only.yaml", """
        vmga_version: "0.2.0"
        profile: observe_only
        allowed_actions: [read, summarize]
        denied_actions: [send, forward]
        domain_policy:
          internal_domains: [example.com]
    """)
    _write(root / "policies" / "draft_assist.yaml", """
        vmga_version: "0.2.0"
        profile: draft_assist
        allowed_actions: [read, summarize, create_draft]
        denied_actions: [send, forward]
        kinetic_requires_approval: true
        domain_policy:
          internal_domains: [example.com]
    """)
    _write(root / "policies" / "scoped_execution.yaml", """
        vmga_version: "0.2.0"
        profile: scoped_execution
        allowed_actions: [read, summarize, create_draft, archive]
        denied_actions: [forward, delete]
        kinetic_requires_approval: true
        approval_required:
          create_draft: true
          archive: true
        domain_policy:
          internal_domains: [example.com]
    """)
    _write(root / "examples" / "advisory_local.yaml", """
        vmga_mode: advisory
        profile: observe_only
        policy_file: ../policies/observe_only.yaml
        gmail:
          mailbox: inbox@example.com
          allowed_domains: [example.com]
    """)
    _write(root / "examples" / "broker_local.yaml", """
        vmga_mode: broker
        profile: scoped_execution
        policy_file: ../policies/scoped_execution.yaml
        broker:
          host: 127.0.0.1
          port: 8088
        gmail:
          mailbox: ops@example.com
          allowed_domains: [example.com]
    """)


def test_release_check_passes_on_safe_repo(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert report.errors == []
    assert report.policies_checked == 3
    assert any(item.code == "schemas_dir_missing" for item in report.warnings)


def test_release_check_flags_secret_like_content(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    _write(tmp_path / "docs" / "unsafe.md", "token: ghp_1234567890abcdef1234567890abcdef1234\n")
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "secret_pattern_github_token" for item in report.errors)


def test_release_check_warns_on_company_placeholder_internal_domain(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    _write(tmp_path / "policies" / "draft_assist.yaml", """
        vmga_version: "0.2.0"
        profile: draft_assist
        allowed_actions: [read, summarize, create_draft]
        denied_actions: [send, forward]
        kinetic_requires_approval: true
        domain_policy:
          internal_domains: [company.com]
    """)
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert report.errors == []
    assert any(item.code == "policy_placeholder_internal_domain" for item in report.warnings)


def test_release_check_flags_personal_gmail_addresses_in_public_docs(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    _write(tmp_path / "docs" / "unsafe.md", "operator mailbox: person@gmail.com\n")
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "public_identity_gmail_address" for item in report.errors)


def test_release_check_scans_example_json_fixtures(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    _write(tmp_path / "examples" / "fixtures" / "unsafe.json", '{"mailbox":"person@gmail.com"}\n')
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "public_identity_gmail_address" for item in report.errors)
    assert any(item.path and item.path.endswith("unsafe.json") for item in report.errors)


def test_release_check_reports_missing_required_file(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    (tmp_path / "CONTRIBUTING.md").unlink()
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "required_file_missing" for item in report.errors)
    assert any(item.path and item.path.endswith("CONTRIBUTING.md") for item in report.errors)


def test_release_check_flags_missing_release_governance_sections(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    _write(tmp_path / "docs" / "release_checklist.md", "# VMGA Release Checklist\n\n## Automated Repo Gates\n")
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "required_doc_phrase_missing" for item in report.errors)
    assert any("Manual Operator Evidence" in item.message for item in report.errors)


def test_release_check_flags_action_catalog_drift(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    path = tmp_path / "docs" / "action_catalog.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"action": "send", "class": "kinetic"', '"action": "send", "class": "non_kinetic"'), encoding="utf-8")
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "action_catalog_class_drift" for item in report.errors)


def test_release_evidence_bundle_redacts_local_values(tmp_path: Path) -> None:
    builder = _load_evidence_builder()
    out = tmp_path / "release"

    result = builder.build_release_bundle(
        out,
        broker_url="http://127.0.0.1:9",
        redact_value=["operator@example.com"],
    )

    payload = (out / "release_evidence.json").read_text(encoding="utf-8")
    assert result == 0
    assert "operator@example.com" not in payload
    assert "operator_evidence_slots" in payload
