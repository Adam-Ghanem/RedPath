from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.audit import AuditLogger


class AIAuditLogger:
    """Separate chained audit stream for model calls and human oversight events."""

    def __init__(self, path: str, *, retention_days: int = 365, max_entries: int = 10_000) -> None:
        self.path = Path(path)
        self.retention_days = max(1, retention_days)
        self.max_entries = max(1, max_entries)
        self._logger = AuditLogger(path)

    @staticmethod
    def hash_context(context: object) -> str:
        serialized = json.dumps(context, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_text(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def record_call(
        self,
        *,
        tenant_id: str,
        actor: str,
        endpoint: str,
        provider: str,
        context_hash: str,
        context_fields: list[str],
        response_summary: dict[str, Any],
        latency_ms: float,
        success: bool,
        error_type: str | None = None,
    ) -> str:
        details: dict[str, Any] = {
            "event_type": "ai_call",
            "tenant_id": tenant_id,
            "endpoint": endpoint,
            "provider": provider,
            "context_hash": context_hash,
            "context_fields": sorted(set(context_fields))[:32],
            "redaction_profile": "secrets-credentials-auth-values-raw-payloads-and-ip-addresses",
            "response_summary": response_summary,
            "latency_ms": round(max(0.0, latency_ms), 2),
            "success": bool(success),
        }
        if error_type:
            details["error_type"] = error_type
        return self._logger.record("ai.call", details, actor=actor)

    def record_feedback(
        self,
        *,
        tenant_id: str,
        actor: str,
        source_type: str,
        source_id: str,
        verdict: str,
        notes_hash: str,
    ) -> str:
        return self._logger.record(
            "ai.feedback",
            {
                "event_type": "human_feedback",
                "tenant_id": tenant_id,
                "source_type": source_type,
                "source_id": source_id,
                "verdict": verdict,
                "notes_hash": notes_hash,
            },
            actor=actor,
        )

    def list_events(self, *, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        result: list[dict[str, Any]] = []
        for line in reversed(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                details = event.get("details", {})
                timestamp = datetime.fromisoformat(str(event.get("timestamp", "")))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if details.get("tenant_id") != tenant_id or timestamp < cutoff:
                continue
            result.append(
                {
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "actor": event.get("actor"),
                    "operation": event.get("operation"),
                    "details": details,
                    "digest": event.get("digest"),
                }
            )
            if len(result) >= min(max(1, limit), self.max_entries):
                break
        return result
