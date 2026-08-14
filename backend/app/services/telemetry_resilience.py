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
SAFE_ERROR_CODES = frozenset(
    {
        "connector_error",
        "schema_drift",
        "checkpoint_invalid",
        "persistence_error",
        "circuit_open",
        "capacity_budget",
    }
)
CIRCUIT_STATES = frozenset({"closed", "open", "half_open"})


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
    circuit_state: str
    circuit_open_until: datetime | None
    capacity_window_started_at: datetime | None
    capacity_events_remaining: int
    capacity_bytes_remaining: int
    freshness_slo_target_seconds: int
    freshness_slo_met: bool | None
    schema_drift_guidance: str | None


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
        circuit_failure_threshold: int = 3,
        circuit_cooldown_seconds: int = 300,
        capacity_window_seconds: int = 60,
        capacity_max_events: int = 1000,
        capacity_max_bytes: int = 4_000_000,
        freshness_slo_target_seconds: int = 900,
    ) -> None:
        if dead_letter_retention_hours < 1 or dead_letter_retention_hours > 24 * 30:
            raise ValueError("dead-letter retention must be between 1 hour and 30 days")
        if dead_letter_max_metadata_bytes < 256 or dead_letter_max_metadata_bytes > 16_384:
            raise ValueError("dead-letter metadata limit is outside the safe range")
        if lag_warning_seconds < 1 or lag_warning_seconds > 7 * 24 * 3600:
            raise ValueError("lag warning threshold is outside the safe range")
        if retention_max_dead_letters < 1 or retention_max_dead_letters > 100_000:
            raise ValueError("dead-letter retention maximum is outside the safe range")
        if circuit_failure_threshold < 1 or circuit_failure_threshold > 20:
            raise ValueError("circuit failure threshold is outside the safe range")
        if circuit_cooldown_seconds < 5 or circuit_cooldown_seconds > 86_400:
            raise ValueError("circuit cooldown is outside the safe range")
        if capacity_window_seconds < 1 or capacity_window_seconds > 3600:
            raise ValueError("capacity window is outside the safe range")
        if capacity_max_events < 1 or capacity_max_events > 100_000:
            raise ValueError("capacity event budget is outside the safe range")
        if capacity_max_bytes < 1024 or capacity_max_bytes > 100_000_000:
            raise ValueError("capacity byte budget is outside the safe range")
        if freshness_slo_target_seconds < 1 or freshness_slo_target_seconds > 7 * 24 * 3600:
            raise ValueError("freshness SLO target is outside the safe range")
        self.session_factory = session_factory
        self.metrics = metrics
        self.dead_letter_retention_hours = dead_letter_retention_hours
        self.dead_letter_max_metadata_bytes = dead_letter_max_metadata_bytes
        self.lag_warning_seconds = lag_warning_seconds
        self.retention_max_dead_letters = retention_max_dead_letters
        self.circuit_failure_threshold = circuit_failure_threshold
        self.circuit_cooldown_seconds = circuit_cooldown_seconds
        self.capacity_window_seconds = capacity_window_seconds
        self.capacity_max_events = capacity_max_events
        self.capacity_max_bytes = capacity_max_bytes
        self.freshness_slo_target_seconds = freshness_slo_target_seconds

    @staticmethod
    def state_id(tenant_id: str, source: str = "wazuh") -> str:
        if not _safe_tenant_or_source(tenant_id) or not _safe_source(source):
            raise ValueError("telemetry tenant or source is invalid")
        return f"{tenant_id}:{source}"[:192]

    def try_start(
        self,
        *,
        tenant_id: str,
        source: str = "wazuh",
        requested_events: int = 1,
        requested_bytes: int = 0,
        now: datetime | None = None,
    ) -> bool:
        if requested_events < 1 or requested_events > self.capacity_max_events:
            raise ValueError("telemetry event capacity request is outside the safe range")
        if requested_bytes < 0 or requested_bytes > self.capacity_max_bytes:
            raise ValueError("telemetry byte capacity request is outside the safe range")
        now = _as_utc(now) or utcnow()
        accepted = False
        rejected_reason = None
        with self.session_factory() as session:
            state = self._get_or_create_state(session, tenant_id, source)
            circuit_open_until = _as_utc(state.circuit_open_until)
            if state.circuit_state == "open":
                if circuit_open_until is None or now < circuit_open_until:
                    rejected_reason = "circuit"
                else:
                    state.circuit_state = "half_open"
                    state.circuit_open_until = None
            if rejected_reason is None:
                capacity_window_started_at = _as_utc(state.capacity_window_started_at)
                window_expired = (
                    capacity_window_started_at is None
                    or now - capacity_window_started_at >= timedelta(seconds=self.capacity_window_seconds)
                )
                if window_expired:
                    state.capacity_window_started_at = now
                    state.capacity_events_reserved = 0
                    state.capacity_bytes_reserved = 0
                if (
                    state.capacity_events_reserved + requested_events > self.capacity_max_events
                    or state.capacity_bytes_reserved + requested_bytes > self.capacity_max_bytes
                ):
                    rejected_reason = "capacity"
                else:
                    state.capacity_events_reserved += requested_events
                    state.capacity_bytes_reserved += requested_bytes
                    state.last_attempt_at = now
                    accepted = True
            session.commit()
        if self.metrics and rejected_reason:
            if rejected_reason == "circuit":
                self.metrics.increment_telemetry("circuit_open_total")
            else:
                self.metrics.increment_telemetry("capacity_rejections_total")
        return accepted

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
        now = _as_utc(now) or utcnow()
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
            state.circuit_state = "closed"
            state.circuit_open_until = None
            state.updated_at = now
            session.commit()
        if self.metrics:
            self.metrics.increment_telemetry("ingest_success_total")
            self.metrics.set_telemetry_gauge("consecutive_failures", 0)
            if last_event_at is not None:
                lag = _lag_seconds(last_event_at, now) or 0
                self.metrics.set_telemetry_gauge("lag_seconds", lag)
                if lag > self.freshness_slo_target_seconds:
                    self.metrics.increment_telemetry("freshness_slo_breaches_total")

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
        now = _as_utc(now) or utcnow()
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
            attempt = state.consecutive_failures
            if attempt >= self.circuit_failure_threshold:
                state.circuit_state = "open"
                state.circuit_open_until = now + timedelta(seconds=self.circuit_cooldown_seconds)
            state.updated_at = now
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
            if attempt >= self.circuit_failure_threshold:
                self.metrics.increment_telemetry("circuit_open_total")
            self.metrics.set_telemetry_gauge("consecutive_failures", attempt)
        return dead_letter_id

    def prune_dead_letters(self, *, tenant_id: str | None = None, now: datetime | None = None) -> int:
        now = _as_utc(now) or utcnow()
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
        now = _as_utc(now) or utcnow()
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
            return ResilienceHealth(
                status="unknown",
                checkpoint_present=False,
                schema_version=None,
                schema_drift_count=0,
                consecutive_failures=0,
                dead_letter_count=int(dead_letters),
                lag_seconds=None,
                last_error_code=None,
                circuit_state="closed",
                circuit_open_until=None,
                capacity_window_started_at=None,
                capacity_events_remaining=self.capacity_max_events,
                capacity_bytes_remaining=self.capacity_max_bytes,
                freshness_slo_target_seconds=self.freshness_slo_target_seconds,
                freshness_slo_met=None,
                schema_drift_guidance=None,
            )
        lag = _lag_seconds(state.last_event_at, now)
        status = "healthy"
        circuit_state = state.circuit_state if state.circuit_state in CIRCUIT_STATES else "open"
        if circuit_state == "open" or state.consecutive_failures or state.schema_drift_count:
            status = "degraded"
        capacity_window_started_at = _as_utc(state.capacity_window_started_at)
        window_active = capacity_window_started_at and (
            now - capacity_window_started_at < timedelta(seconds=self.capacity_window_seconds)
        )
        events_reserved = state.capacity_events_reserved if window_active else 0
        bytes_reserved = state.capacity_bytes_reserved if window_active else 0
        return ResilienceHealth(
            status=status,
            checkpoint_present=bool(state.checkpoint_cursor),
            schema_version=state.schema_version,
            schema_drift_count=state.schema_drift_count,
            consecutive_failures=state.consecutive_failures,
            dead_letter_count=int(dead_letters),
            lag_seconds=lag,
            last_error_code=state.last_error_code,
            circuit_state=circuit_state,
            circuit_open_until=_as_utc(state.circuit_open_until),
            capacity_window_started_at=capacity_window_started_at if window_active else now,
            capacity_events_remaining=max(0, self.capacity_max_events - events_reserved),
            capacity_bytes_remaining=max(0, self.capacity_max_bytes - bytes_reserved),
            freshness_slo_target_seconds=self.freshness_slo_target_seconds,
            freshness_slo_met=None if lag is None else lag <= self.freshness_slo_target_seconds,
            schema_drift_guidance=_schema_drift_guidance(state.schema_drift_count),
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


def _schema_drift_guidance(drift_count: int) -> str | None:
    return "review_provider_schema_contract" if drift_count else None


def _safe_tenant_or_source(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and all(
        character.isalnum() or character in "_.:-" for character in value
    )


def _safe_source(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 32 and all(
        character.isalnum() or character in "_.:-" for character in value
    )


def _safe_provider_id(provider_id: Any) -> bool:
    return (
        isinstance(provider_id, str)
        and 0 < len(provider_id) <= MAX_PROVIDER_ID_LENGTH
        and all(ord(char) >= 32 for char in provider_id)
    )


def _signature(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _lag_seconds(last_event_at: datetime | None, now: datetime) -> float | None:
    normalized = _as_utc(last_event_at)
    if normalized is None:
        return None
    return max(0.0, (now.astimezone(timezone.utc) - normalized).total_seconds())


def _bounded_metadata(metadata: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return metadata
    return {
        "error_code": str(metadata.get("error_code", "connector_error"))[:64],
        "attempt": int(metadata.get("attempt", 0)),
    }
