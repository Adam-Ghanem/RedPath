from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL audit log with a chained integrity digest."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._previous_digest = "GENESIS"
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._previous_digest = json.loads(line)["digest"]

    def record(self, operation: str, details: dict[str, Any], *, actor: str = "api") -> str:
        event_id = str(uuid.uuid4())
        event = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "operation": operation,
            "details": details,
            "previous_digest": self._previous_digest,
        }
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
        event["digest"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        self._previous_digest = event["digest"]
        return event_id
