"""Tests for the offline VMGA release check."""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "vmga_release_check.py"


def _load_release_checker():
    spec = importlib.util.spec_from_file_location("vmga_release_check", SCRIPT_PATH)
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
    _write(root / "docs" / "release_checklist.md", "Release checklist.\n")
    _write(root / "docs" / "deployment_runbook.md", "Deployment runbook.\n")
    _write(root / "docs" / "openclaw_integration.md", "OpenClaw integration.\n")
    _write(root / "docs" / "hermes_integration.md", "Hermes integration.\n")
    _write(root / "docs" / "dsovs_readiness.md", "DSOVS readiness.\n")
    _write(root / "docs" / "evidence.md", "VMGA does not claim prompt-injection prevention, DLP, host compromise protection, browser/session isolation, compliance certification, or security of Hermes/OpenClaw internals.\n")
    _write(root / "docs" / "gmail_backend_options.md", "VMGA does not claim prompt-injection prevention, DLP, host compromise protection, browser/session isolation, compliance certification, or security of Hermes/OpenClaw internals.\n")
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


def test_release_check_reports_missing_required_file(tmp_path: Path) -> None:
    _populate_safe_repo(tmp_path)
    (tmp_path / "CONTRIBUTING.md").unlink()
    checker = _load_release_checker()

    report = checker.run_release_check(tmp_path)

    assert any(item.code == "required_file_missing" for item in report.errors)
    assert any(item.path and item.path.endswith("CONTRIBUTING.md") for item in report.errors)
