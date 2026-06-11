#!/usr/bin/env python3
"""Offline VMGA release check for docs, examples, and policy hygiene.

This script stays offline and only inspects repository files. It validates that
shipped policy YAML loads, required release files exist, claim-hygiene language
is present, optional schema directories are accounted for, and obvious secret
patterns are absent from docs and examples.
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vmga.vmga_adapter import load_vmga_policy
from vmga.redaction import SECRET_PATTERNS


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    path: Optional[str] = None
    severity: str = "error"


@dataclass
class ReleaseReport:
    root: str
    policies_checked: int = 0
    files_scanned: int = 0
    errors: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)

    def add(self, severity: str, code: str, message: str, path: Optional[Path] = None) -> None:
        finding = Finding(code=code, message=message, path=str(path) if path else None, severity=severity)
        if severity == "warning":
            self.warnings.append(finding)
        else:
            self.errors.append(finding)

    @property
    def exit_code(self) -> int:
        return 1 if self.errors else 0

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "policies_checked": self.policies_checked,
            "files_scanned": self.files_scanned,
            "errors": [asdict(item) for item in self.errors],
            "warnings": [asdict(item) for item in self.warnings],
            "exit_code": self.exit_code,
        }


REQUIRED_FILES = [
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/release_checklist.md",
    "docs/deployment_runbook.md",
    "docs/openclaw_integration.md",
    "docs/hermes_integration.md",
    "docs/dsovs_readiness.md",
    "docs/evidence.md",
    "docs/gmail_backend_options.md",
]

CLAIM_HYGIENE_PATTERNS: dict[str, re.Pattern[str]] = {
    "prompt_injection": re.compile(r"does not claim[\s\S]{0,220}?prompt[- ]injection prevention", re.IGNORECASE),
    "dlp": re.compile(r"does not claim[\s\S]{0,220}?\bDLP\b", re.IGNORECASE),
    "host_compromise": re.compile(r"does not claim[\s\S]{0,220}?host compromise protection", re.IGNORECASE),
    "browser_isolation": re.compile(r"does not claim[\s\S]{0,220}?browser/session isolation", re.IGNORECASE),
    "compliance_cert": re.compile(r"does not claim[\s\S]{0,220}?compliance certification", re.IGNORECASE),
    "internals": re.compile(r"does not claim[\s\S]{0,260}?security of Hermes/OpenClaw internals", re.IGNORECASE),
}

PUBLIC_IDENTITY_PATTERNS: dict[str, re.Pattern[str]] = {
    "gmail_address": re.compile(r"\b[A-Za-z0-9._%+-]+@gmail\.com\b", re.IGNORECASE),
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _iter_files(root: Path, patterns: Sequence[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        files.extend(sorted(root.glob(pattern)))
    return [path for path in files if path.is_file()]


def _scan_patterns(report: ReleaseReport, files: Iterable[Path], patterns: dict[str, re.Pattern[str]], *, severity: str, code_prefix: str) -> None:
    for path in files:
        text = _read_text(path)
        for code, pattern in patterns.items():
            if pattern.search(text):
                report.add(
                    severity,
                    f"{code_prefix}_{code}",
                    f"Found pattern '{code}' in {path.relative_to(Path(report.root))}",
                    path=path,
                )


def _required_files(report: ReleaseReport, root: Path) -> None:
    for rel in REQUIRED_FILES:
        path = root / rel
        if not path.exists():
            report.add("error", "required_file_missing", f"Required file is missing: {rel}", path=path)


def _check_schema_dir(report: ReleaseReport, root: Path) -> None:
    schema_dir = root / "schemas"
    if schema_dir.is_dir():
        return
    report.add(
        "warning",
        "schemas_dir_missing",
        "schemas/ directory is absent; schema-backed release checks are unavailable in this repo snapshot.",
        path=schema_dir,
    )


def _check_policy_yaml(report: ReleaseReport, root: Path) -> None:
    policy_dir = root / "policies"
    if not policy_dir.is_dir():
        report.add("error", "policy_dir_missing", "policies/ directory is missing", path=policy_dir)
        return

    policy_files = sorted(
        [*policy_dir.glob("*.yaml"), *policy_dir.glob("*.yml")]
    )
    if not policy_files:
        report.add("error", "policy_files_missing", "No policy YAML files were found", path=policy_dir)
        return

    for path in policy_files:
        try:
            load_vmga_policy(str(path))
            report.policies_checked += 1
        except Exception as exc:  # noqa: BLE001 - release check should surface loader failures
            report.add("error", "policy_load_failed", f"Policy YAML failed to load: {exc}", path=path)


def _check_claim_hygiene(report: ReleaseReport, files: Iterable[Path]) -> None:
    file_map = {path: " ".join(_read_text(path).split()) for path in files}
    for code, pattern in CLAIM_HYGIENE_PATTERNS.items():
        if any(pattern.search(text) for text in file_map.values()):
            continue
        report.add(
            "error",
            f"claim_hygiene_missing_{code}",
            f"Missing claim-hygiene phrase for '{code}'",
        )


def _collect_scannable_files(root: Path) -> list[Path]:
    files = _iter_files(
        root,
        [
            "README.md",
            "docs/**/*.md",
            "examples/**/*.yaml",
            "examples/**/*.yml",
            "policies/**/*.yaml",
            "policies/**/*.yml",
        ],
    )

    integrations = root / "integrations"
    if integrations.is_dir():
        for path in integrations.rglob("*"):
            if path.is_file() and path.suffix in {".md", ".yaml", ".yml"} and "examples" in path.parts:
                files.append(path)

    # Stable order and dedupe.
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in sorted(files):
        if path not in seen:
            unique.append(path)
            seen.add(path)
    return unique


CONFLICT_MARKER_PATTERN = re.compile(r"^(<{7}|>{7})( |$)", re.MULTILINE)
CONFLICT_SCAN_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".ts", ".js", ".json", ".toml", ".txt", ".cfg", ".ini"}
CONFLICT_SCAN_EXCLUDED_PARTS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}


def _check_conflict_markers(report: ReleaseReport, root: Path) -> None:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in CONFLICT_SCAN_SUFFIXES:
            continue
        if CONFLICT_SCAN_EXCLUDED_PARTS.intersection(path.parts):
            continue
        if CONFLICT_MARKER_PATTERN.search(_read_text(path)):
            report.add(
                "error",
                "merge_conflict_marker",
                f"Unresolved merge conflict marker in {path.relative_to(root)}",
                path=path,
            )


def run_release_check(root: Path | str | None = None) -> ReleaseReport:
    root_path = Path(root) if root is not None else REPO_ROOT
    report = ReleaseReport(root=str(root_path))

    _required_files(report, root_path)
    _check_schema_dir(report, root_path)
    _check_policy_yaml(report, root_path)

    scannable_files = _collect_scannable_files(root_path)
    report.files_scanned = len(scannable_files)

    _check_conflict_markers(report, root_path)
    _check_claim_hygiene(report, scannable_files)
    _scan_patterns(report, scannable_files, SECRET_PATTERNS, severity="error", code_prefix="secret_pattern")
    _scan_patterns(report, scannable_files, PUBLIC_IDENTITY_PATTERNS, severity="error", code_prefix="public_identity")

    return report


def _print_human(report: ReleaseReport) -> None:
    print(f"VMGA release check: {report.exit_code == 0 and 'PASS' or 'FAIL'}")
    print(f"root: {report.root}")
    print(f"policies checked: {report.policies_checked}")
    print(f"files scanned: {report.files_scanned}")
    if report.errors:
        print("errors:")
        for item in report.errors:
            location = f" [{item.path}]" if item.path else ""
            print(f"  - {item.code}: {item.message}{location}")
    if report.warnings:
        print("warnings:")
        for item in report.warnings:
            location = f" [{item.path}]" if item.path else ""
            print(f"  - {item.code}: {item.message}{location}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Offline VMGA release check")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="Repository root to check")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output")
    args = parser.parse_args(argv)

    report = run_release_check(args.root)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_human(report)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
