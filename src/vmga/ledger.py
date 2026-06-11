"""Simple append-only JSONL ledger for VMGA evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .evidence_integrity import canonical_json_line


class JSONLVMGALedger:
    def __init__(self, path: str | Path, *, rotate_bytes: int = 0, backup_count: int = 5):
        self.path = Path(path)
        self.rotate_bytes = max(0, int(rotate_bytes))
        self.backup_count = max(1, int(backup_count))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self, next_line_bytes: int) -> None:
        if not self.rotate_bytes or not self.path.exists():
            return
        if self.path.stat().st_size + next_line_bytes <= self.rotate_bytes:
            return
        oldest = self.path.with_name(f"{self.path.name}.{self.backup_count}")
        if oldest.exists():
            oldest.unlink()
        for index in range(self.backup_count - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists():
                source.rename(self.path.with_name(f"{self.path.name}.{index + 1}"))
        self.path.rename(self.path.with_name(f"{self.path.name}.1"))

    def append(self, event: Dict[str, Any]) -> None:
        line = canonical_json_line(event)
        self.append_line(line)

    def append_line(self, line: str) -> None:
        if not line.endswith("\n"):
            raise ValueError("ledger lines must end with newline")
        self._rotate_if_needed(len(line.encode("utf-8")))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def read_all(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        events: List[Dict[str, Any]] = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
        return events


class LedgerVestaAdapter:
    """Minimal vesta-compatible adapter around a VMGA JSONL ledger."""

    def __init__(self, ledger: JSONLVMGALedger):
        self.audit_ledger = ledger

    def execute(self, request: Any, handler: Any) -> Any:
        result = handler(request)

        class ExecutionResult:
            request_id = getattr(request, "request_id", "vmga-request")
            duration_ms = 0
            output = result

        return ExecutionResult()
