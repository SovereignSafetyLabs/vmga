"""Runtime enforcement posture checks for VMGA deployments."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PASS = "pass"
WARN = "warn"
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass
class PostureConfig:
    host: str = "127.0.0.1"
    backend: str = "fake"
    policy_path: str = "policies/draft_assist.yaml"
    state_db_path: str = ".vmga/state.sqlite3"
    ledger_path: str = ".vmga/evidence.jsonl"
    ledger_rotate_bytes: int = 0
    bearer_token_set: bool = False
    allow_unauthenticated: bool = False
    gog_binary: str = ""
    gog_home: Optional[str] = None
    approval_auth: str = "hmac"
    evidence_integrity: str = "append_only"
    agent_roots: List[str] = field(default_factory=list)
    direct_bypass_attested: bool = False
    direct_bypass_evidence: str = ""


def _resolve(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _path_under_roots(path: str | Path, roots: Iterable[str | Path]) -> Optional[str]:
    resolved_path = _resolve(path)
    for root in roots:
        resolved_root = _resolve(root)
        if _is_relative_to(resolved_path, resolved_root):
            return str(resolved_root)
    return None


def _check(check_id: str, status: str, summary: str, *, detail: str = "") -> Dict[str, str]:
    payload = {"id": check_id, "status": status, "summary": summary}
    if detail:
        payload["detail"] = detail
    return payload


def assess_posture(config: PostureConfig) -> Dict[str, Any]:
    """Return a conservative deployment posture report.

    This is a runtime self-check, not a formal sandbox proof. Facts that VMGA
    cannot observe locally remain ``unknown`` and never count toward hard-ready.
    """

    agent_roots = config.agent_roots
    checks: List[Dict[str, str]] = []

    if config.bearer_token_set:
        checks.append(_check("broker_auth", PASS, "Broker bearer authentication is configured."))
    elif config.allow_unauthenticated and config.host in {"127.0.0.1", "::1", "localhost"}:
        checks.append(_check("broker_auth", WARN, "Loopback unauthenticated mode is enabled for development."))
    else:
        checks.append(_check("broker_auth", FAIL, "Broker authentication is not configured."))

    if config.backend == "fake":
        checks.append(_check("mailbox_backend", WARN, "Fake backend is active; no live Gmail boundary is being enforced."))
    elif config.backend == "gogcli":
        binary_name = Path(config.gog_binary or "").name
        if binary_name == "gog-agent-safe":
            checks.append(_check("mailbox_backend", PASS, "gog-agent-safe backend is configured."))
        elif binary_name:
            checks.append(_check("mailbox_backend", WARN, "gogcli backend is configured without the gog-agent-safe wrapper.", detail=config.gog_binary))
        else:
            checks.append(_check("mailbox_backend", UNKNOWN, "gogcli backend binary could not be identified."))
    else:
        checks.append(_check("mailbox_backend", UNKNOWN, f"Unknown backend posture: {config.backend}"))

    if config.approval_auth == "signature":
        checks.append(_check("approval_boundary", PASS, "Asymmetric approval mode is configured. Verify private-key isolation separately."))
    elif config.approval_auth == "hmac":
        checks.append(_check("approval_boundary", WARN, "HMAC approval is broker-forgeable; hard approval enforcement requires signature mode."))
    else:
        checks.append(_check("approval_boundary", UNKNOWN, f"Unknown approval mode: {config.approval_auth}"))

    if config.evidence_integrity in {"hmac_chain", "signed_checkpoint", "external_anchor"}:
        checks.append(_check("evidence_integrity", PASS, f"Evidence integrity mode configured: {config.evidence_integrity}."))
    elif config.evidence_integrity == "append_only":
        checks.append(_check("evidence_integrity", WARN, "Evidence is append-only/advisory; integrity anchoring is not configured."))
    else:
        checks.append(_check("evidence_integrity", UNKNOWN, f"Unknown evidence integrity mode: {config.evidence_integrity}"))

    for check_id, path_value, label in (
        ("policy_path", config.policy_path, "Policy path"),
        ("state_path", config.state_db_path, "State DB path"),
        ("ledger_path", config.ledger_path, "Evidence ledger path"),
    ):
        if not agent_roots:
            checks.append(_check(check_id, UNKNOWN, f"{label} isolation cannot be assessed until operator supplies --agent-root.", detail=str(_resolve(path_value))))
            continue
        root = _path_under_roots(path_value, agent_roots)
        if root:
            checks.append(_check(check_id, WARN, f"{label} is under an agent/root workspace; hard-boundary claims require operator-owned paths.", detail=f"path={_resolve(path_value)} root={root}"))
        else:
            checks.append(_check(check_id, PASS, f"{label} is not under the configured agent root(s).", detail=str(_resolve(path_value))))

    if config.backend == "gogcli":
        if config.gog_home:
            root = _path_under_roots(config.gog_home, agent_roots)
            if root:
                checks.append(_check("gog_home", WARN, "gog home is under an agent/root workspace; OAuth material may be agent-readable.", detail=f"path={_resolve(config.gog_home)} root={root}"))
            else:
                checks.append(_check("gog_home", PASS, "gog home is not under the configured agent root(s).", detail=str(_resolve(config.gog_home))))
        else:
            checks.append(_check("gog_home", UNKNOWN, "gog home was not configured; credential isolation cannot be assessed."))

    if config.ledger_rotate_bytes > 0:
        checks.append(_check("evidence_rotation", PASS, "Evidence ledger rotation is configured.", detail=f"rotate_bytes={config.ledger_rotate_bytes}"))
    else:
        checks.append(_check("evidence_rotation", WARN, "Evidence ledger rotation is not configured."))

    if config.direct_bypass_attested and config.direct_bypass_evidence:
        checks.append(_check("direct_gmail_bypass", PASS, "Operator attests direct Gmail/Workspace bypass closure evidence exists.", detail=config.direct_bypass_evidence))
    else:
        checks.append(_check("direct_gmail_bypass", UNKNOWN, "VMGA cannot locally prove agents lack direct Gmail/Workspace access; supply explicit bypass-closure attestation and evidence before hard-enforcement claims."))
    checks.append(_check("single_process_boundary", PASS, "Built-in broker is a single-process control plane; do not run multiple broker processes against one state DB for hard claims."))

    hard_blockers = [item for item in checks if item["status"] in {FAIL, WARN, UNKNOWN}]
    if not hard_blockers:
        mode = "hard_enforcement_ready"
    elif any(item["status"] == FAIL for item in hard_blockers):
        mode = "advisory"
    elif any(item["status"] == UNKNOWN for item in hard_blockers):
        mode = "cannot_determine"
    else:
        mode = "advisory"

    return {
        "schema_version": "0.1",
        "mode": mode,
        "hard_enforcement_ready": mode == "hard_enforcement_ready",
        "summary": _summary_for_mode(mode),
        "checks": checks,
    }


def _summary_for_mode(mode: str) -> str:
    if mode == "hard_enforcement_ready":
        return "Runtime posture checks found no local blockers to hard-enforcement claims."
    if mode == "cannot_determine":
        return "Runtime posture has unknowns; treat this deployment as advisory until resolved."
    return "Runtime posture is advisory; hard-enforcement preconditions are not met."


def print_posture_summary(report: Dict[str, Any]) -> str:
    return f"VMGA posture: {report['mode']} - {report['summary']}"
