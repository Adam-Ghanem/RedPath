from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, func, select

from app.core.observability import MetricsRegistry
from app.db.models import TelemetryDeadLetter, TelemetryIngestionState, utcnow

EXPECTED_SCHEMA_VERSION = "wazuh-alert-v1"
CURSOR_VERSION = "v1"
MAX_CURSOR_BYTES = 1024
MAX_PROVIDER_ID_LENGTH = 128
SAFE_ERROR_CODES = frozenset({"connector_error", "schema_drift", "checkpoint_invalid", "persistence_error"})


@dataclass(frozen=True)
class Checkpoint:
    observed_at: datetime
    provider_id: str
    schema_version: str = EXPECTED_SCHEMA_VERSION


@dataclass(frozen=True)
class SchemaObservation:
    schema_version: str
    signature: str
    drift_reason: str | None = None


@dataclass(frozen=True)
class ResilienceHealth:
    status: str
    checkpoint_present: bool
    schema_version: str | None
    schema_drift_count: int
    consecutive_failures: int
    dead_letter_count: int
    lag_seconds: float | None
    last_error_code: str | None


class CheckpointCodec:
    """Encode and validate opaque provider checkpoints without exposing raw query state."""

    @staticmethod
    def encode(checkpoint: Checkpoint) -> str:
        if checkpoint.observed_at.tzinfo is None:
            raise ValueError("checkpoint timestamp must be timezone-aware")
        if not _safe_provider_id(checkpoint.provider_id):
            raise ValueError("checkpoint provider ID is invalid")
        payload = {
            "v": CURSOR_VERSION,
            "observed_at": checkpoint.observed_at.astimezone(timezone.utc).isoformat(),
            "provider_id": checkpoint.provider_id,
            "schema_version": checkpoint.schema_version[:64],
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).rstrip(b"=")
        if len(encoded) > MAX_CURSOR_BYTES:
            raise ValueError("checkpoint exceeds the configured size limit")
        return encoded.decode("ascii")

    @staticmethod
    def decode(cursor: str) -> Checkpoint:
        if not isinstance(cursor, str) or not cursor or len(cursor) > MAX_CURSOR_BYTES:
            raise ValueError("checkpoint is invalid")
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error) as exc:
            raise ValueError("checkpoint is invalid") from exc
        if not isinstance(payload, dict) or payload.get("v") != CURSOR_VERSION:
            raise ValueError("checkpoint version is unsupported")
        observed_at = payload.get("observed_at")
        provider_id = payload.get("provider_id")
        schema_version = payload.get("schema_version", EXPECTED_SCHEMA_VERSION)
        if not isinstance(observed_at, str) or not isinstance(schema_version, str):
            raise ValueError("checkpoint fields are invalid")
        try:
            parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("checkpoint timestamp is invalid") from exc
        if parsed.tzinfo is None or not _safe_provider_id(provider_id):
            raise ValueError("checkpoint fields are invalid")
        return Checkpoint(parsed.astimezone(timezone.utc), provider_id, schema_version[:64])


def inspect_schema(document: dict[str, Any]) -> SchemaObservation:
    source = document.get("_source", document) if isinstance(document, dict) else {}
    if not isinstance(source, dict):
        return SchemaObservation("unknown", _signature({}), "payload_not_object")
    signature_payload = {
        key: type(value).__name__
        for key, value in sorted(source.items())
        if isinstance(key, str) and len(key) <= 64
    }
    signature = hashlib.sha256(
        json.dumps(signature_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    if not isinstance(source.get("rule"), dict):
        return SchemaObservation("unknown", signature, "missing_rule_object")
    return SchemaObservation(EXPECTED_SCHEMA_VERSION, signature)


class TelemetryResilienceStore:
    """Tenant-scoped local recovery state; it never sends commands to a connector."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        metrics: MetricsRegistry | None = None,
        dead_letter_retention_hours: int = 72,
        dead_letter_max_metadata_bytes: int = 2048,
        lag_warning_seconds: int = 900,
        retention_max_dead_letters: int = 1000,
    ) -> None:
        if dead_letter_retention_hours < 1 or dead_letter_retention_hours > 24 * 30:
            raise ValueError("dead-letter retention must be between 1 hour and 30 days")
        if dead_letter_max_metadata_bytes < 256 or dead_letter_max_metadata_bytes > 16_384:
            raise ValueError("dead-letter metadata limit is outside the safe range")
        if lag_warning_seconds < 1 or lag_warning_seconds > 7 * 24 * 3600:
            raise ValueError("lag warning threshold is outside the safe range")
        if retention_max_dead_letters < 1 or retention_max_dead_letters > 100_000:
            raise ValueError("dead-letter retention maximum is outside the safe range")
        self.session_factory = session_factory
        self.metrics = metrics
        self.dead_letter_retention_hours = dead_letter_retention_hours
        self.dead_letter_max_metadata_bytes = dead_letter_max_metadata_bytes
        self.lag_warning_seconds = lag_warning_seconds
        self.retention_max_dead_letters = retention_max_dead_letters

    @staticmethod
    def state_id(tenant_id: str, source: str = "wazuh") -> str:
        return f"{tenant_id}:{source}"[:192]

    def get_checkpoint(self, tenant_id: str, source: str = "wazuh") -> str | None:
        with self.session_factory() as session:
            state = session.get(TelemetryIngestionState, self.state_id(tenant_id, source))
            return state.checkpoint_cursor if state else None

    def mark_success(
        self,
        *,
        tenant_id: str,
        checkpoint_cursor: str | None,
        schema_version: str,
        last_event_at: datetime | None,
        now: datetime | None = None,
        source: str = "wazuh",
    ) -> None:
        now = now or utcnow()
        with self.session_factory() as session:
            state = self._get_or_create_state(session, tenant_id, source)
            state.checkpoint_cursor = checkpoint_cursor
            state.cursor_version = CURSOR_VERSION if checkpoint_cursor else None
            state.schema_version = schema_version[:64]
            state.last_success_at = now
            state.last_event_at = last_event_at
            state.last_lag_seconds = _lag_seconds(last_event_at, now)
            state.consecutive_failures = 0
            state.last_error_code = None
            state.updated_at = now
            session.commit()
        if self.metrics:
            self.metrics.increment_telemetry("ingest_success_total")
            self.metrics.set_telemetry_gauge("consecutive_failures", 0)
            if last_event_at is not None:
                self.metrics.set_telemetry_gauge("lag_seconds", _lag_seconds(last_event_at, now) or 0)

    def record_failure(
        self,
        *,
        tenant_id: str,
        error_code: str,
        checkpoint_cursor: str | None = None,
        schema_version: str | None = None,
        schema_signature: str | None = None,
        now: datetime | None = None,
        source: str = "wazuh",
    ) -> str:
        now = now or utcnow()
        safe_code = error_code if error_code in SAFE_ERROR_CODES else "connector_error"
        with self.session_factory() as session:
            state = self._get_or_create_state(session, tenant_id, source)
            state.consecutive_failures += 1
            state.last_error_code = safe_code
            state.last_error_at = now
            if schema_version:
                state.schema_version = schema_version[:64]
            if safe_code == "schema_drift":
                state.schema_drift_count += 1
            state.updated_at = now
            attempt = state.consecutive_failures
            metadata = _bounded_metadata(
                {
                    "error_code": safe_code,
                    "attempt": attempt,
                    "checkpoint_present": bool(checkpoint_cursor),
                    "schema_version": (schema_version or EXPECTED_SCHEMA_VERSION)[:64],
                    "schema_signature": (schema_signature or "")[:16],
                },
                self.dead_letter_max_metadata_bytes,
            )
            dead_letter = TelemetryDeadLetter(
                id=str(uuid4()),
                tenant_id=tenant_id,
                source=source,
                error_code=safe_code,
                attempt=attempt,
                metadata_json=metadata,
                retry_after_at=now + timedelta(seconds=min(3600, 5 * (2 ** min(attempt - 1, 9)))),
                expires_at=now + timedelta(hours=self.dead_letter_retention_hours),
                created_at=now,
            )
            session.add(dead_letter)
            dead_letter_id = dead_letter.id
            session.commit()
        if self.metrics:
            self.metrics.increment_telemetry("ingest_failures_total")
            self.metrics.increment_telemetry("dead_letters_total")
            if safe_code == "schema_drift":
                self.metrics.increment_telemetry("schema_drift_total")
            self.metrics.set_telemetry_gauge("consecutive_failures", attempt)
        return dead_letter_id

    def prune_dead_letters(self, *, tenant_id: str | None = None, now: datetime | None = None) -> int:
        now = now or utcnow()
        with self.session_factory() as session:
            query = (
                select(TelemetryDeadLetter.id)
                .where(TelemetryDeadLetter.expires_at <= now)
                .order_by(TelemetryDeadLetter.created_at.asc())
                .limit(self.retention_max_dead_letters)
            )
            if tenant_id:
                query = query.where(TelemetryDeadLetter.tenant_id == tenant_id)
            ids = list(session.scalars(query).all())
            if ids:
                session.execute(delete(TelemetryDeadLetter).where(TelemetryDeadLetter.id.in_(ids)))
                session.commit()
        if self.metrics and ids:
            self.metrics.increment_telemetry("retention_pruned_total", len(ids))
        return len(ids)

    def health(self, *, tenant_id: str, now: datetime | None = None, source: str = "wazuh") -> ResilienceHealth:
        now = now or utcnow()
        with self.session_factory() as session:
            state = session.get(TelemetryIngestionState, self.state_id(tenant_id, source))
            dead_letters = session.scalar(
                select(func.count(TelemetryDeadLetter.id)).where(
                    TelemetryDeadLetter.tenant_id == tenant_id,
                    TelemetryDeadLetter.source == source,
                    TelemetryDeadLetter.expires_at > now,
                )
            ) or 0
        if state is None:
            return ResilienceHealth("unknown", False, None, 0, 0, int(dead_letters), None, None)
        lag = _lag_seconds(state.last_event_at, now)
        status = "healthy"
        if state.consecutive_failures or state.schema_drift_count:
            status = "degraded"
        return ResilienceHealth(
            status,
            bool(state.checkpoint_cursor),
            state.schema_version,
            state.schema_drift_count,
            state.consecutive_failures,
            int(dead_letters),
            lag,
            state.last_error_code,
        )

    def _get_or_create_state(self, session: Any, tenant_id: str, source: str) -> TelemetryIngestionState:
        state = session.get(TelemetryIngestionState, self.state_id(tenant_id, source))
        if state is None:
            state = TelemetryIngestionState(
                id=self.state_id(tenant_id, source),
                tenant_id=tenant_id,
                source=source,
                consecutive_failures=0,
                schema_drift_count=0,
            )
            session.add(state)
            session.flush()
        return state


def _safe_provider_id(provider_id: Any) -> bool:
    return (
        isinstance(provider_id, str)
        and 0 < len(provider_id) <= MAX_PROVIDER_ID_LENGTH
        and all(ord(char) >= 32 for char in provider_id)
    )


def _signature(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _lag_seconds(last_event_at: datetime | None, now: datetime) -> float | None:
    if last_event_at is None:
        return None
    return max(0.0, (now.astimezone(timezone.utc) - last_event_at.astimezone(timezone.utc)).total_seconds())


def _bounded_metadata(metadata: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return metadata
    return {
        "error_code": str(metadata.get("error_code", "connector_error"))[:64],
        "attempt": int(metadata.get("attempt", 0)),
    }
