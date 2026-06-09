"""Simple append-only JSONL ledger for VMGA evidence."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List


class JSONLVMGALedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
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
