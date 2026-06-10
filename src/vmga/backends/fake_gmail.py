"""Safe fake Gmail backend for tests, demos, and CI."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class FakeGmailBackend:
    messages: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    operations: List[Dict[str, Any]] = field(default_factory=list)

    def search(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        matches = [
            {"message_id": mid, **message}
            for mid, message in self.messages.items()
            if query.lower() in str(message).lower()
        ]
        return {"messages": matches[:max(0, int(max_results))], "backend": "fake"}

    def read(self, message_id: str) -> Dict[str, Any]:
        return {"message_id": message_id, **self.messages.get(message_id, {"subject": "Fake message", "body": ""})}

    def execute(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        operation = {"action": action, "payload": payload}
        self.operations.append(operation)
        return {"status": "FAKE_EXECUTED", "operation": operation, "backend": "fake"}

    def download_attachment(self, attachment_id: str, output_dir: str | Path) -> Dict[str, Any]:
        output_path = Path(output_dir) / f"{attachment_id}.txt"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("fake attachment content\n", encoding="utf-8")
        operation = {"action": "download_attachment", "attachment_id": attachment_id, "path": str(output_path)}
        self.operations.append(operation)
        return {"status": "FAKE_EXECUTED", "operation": operation, "backend": "fake"}
