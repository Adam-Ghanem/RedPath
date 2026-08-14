from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from time import monotonic
from typing import Any, Callable, Generic, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.request_context import Principal

MAX_IDEMPOTENCY_KEY_LENGTH = 128
MAX_IDEMPOTENCY_ENTRIES = 10_000
MAX_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60
MAX_RETRY_ATTEMPTS = 5
MAX_RETRY_DELAY_SECONDS = 300


class FailureCode(StrEnum):
    """Stable failure taxonomy for safe internal workflows."""

    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION_REQUIRED = "authentication_required"
    PERMISSION_DENIED = "permission_denied"
    TENANT_MISMATCH = "tenant_mismatch"
    CONFLICT = "conflict"
    IDEMPOTENCY_IN_PROGRESS = "idempotency_in_progress"
    RATE_LIMITED = "rate_limited"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    TIMEOUT = "timeout"
    VALIDATION_FAILED = "validation_failed"
    INTERNAL_ERROR = "internal_error"


class RetryPolicy(BaseModel):
    """Deterministic bounded backoff instructions; no scheduler or worker is created."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_attempts: int = Field(default=3, ge=1, le=MAX_RETRY_ATTEMPTS)
    initial_delay_seconds: float = Field(default=0.25, ge=0, le=30)
    multiplier: float = Field(default=2.0, ge=1, le=4)
    max_delay_seconds: float = Field(default=30, ge=0, le=MAX_RETRY_DELAY_SECONDS)

    def delay_for(self, attempt: int) -> float:
        if attempt < 1:
            raise ValueError("retry attempt must be positive")
        return min(
            self.max_delay_seconds,
            self.initial_delay_seconds * (self.multiplier ** (attempt - 1)),
        )

    def should_retry(self, *, attempt: int, failure_code: FailureCode) -> bool:
        if attempt >= self.max_attempts:
            return False
        return failure_code in {
            FailureCode.RATE_LIMITED,
            FailureCode.DEPENDENCY_UNAVAILABLE,
            FailureCode.TIMEOUT,
        }


class RetryDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt: int = Field(ge=1, le=MAX_RETRY_ATTEMPTS)
    retry: bool
    delay_seconds: float = Field(ge=0, le=MAX_RETRY_DELAY_SECONDS)
    failure_code: FailureCode


class FailureEnvelope(BaseModel):
    """Safe deterministic failure response with no raw exception or payload fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^\d+\.\d+$")
    code: FailureCode
    message: str = Field(min_length=1, max_length=256)
    request_id: str = Field(min_length=1, max_length=128)
    retryable: bool = False
    retry_after_seconds: int | None = Field(default=None, ge=0, le=MAX_RETRY_DELAY_SECONDS)

    @model_validator(mode="after")
    def validate_retry_hint(self) -> "FailureEnvelope":
        if self.retry_after_seconds is not None and not self.retryable:
            raise ValueError("retry hint requires a retryable failure")
        return self


def failure_from_code(
    code: FailureCode,
    *,
    request_id: str,
    retry_after_seconds: int | None = None,
) -> FailureEnvelope:
    messages = {
        FailureCode.INVALID_REQUEST: "The request is invalid.",
        FailureCode.AUTHENTICATION_REQUIRED: "Authentication is required.",
        FailureCode.PERMISSION_DENIED: "The operation is not permitted.",
        FailureCode.TENANT_MISMATCH: "The resource does not belong to the authenticated tenant.",
        FailureCode.CONFLICT: "The operation conflicts with current state.",
        FailureCode.IDEMPOTENCY_IN_PROGRESS: "An equivalent operation is already in progress.",
        FailureCode.RATE_LIMITED: "The operation is rate limited.",
        FailureCode.DEPENDENCY_UNAVAILABLE: "A required dependency is unavailable.",
        FailureCode.TIMEOUT: "The operation timed out.",
        FailureCode.VALIDATION_FAILED: "The operation could not be validated.",
        FailureCode.INTERNAL_ERROR: "The operation could not be completed.",
    }
    retryable = code in {
        FailureCode.RATE_LIMITED,
        FailureCode.DEPENDENCY_UNAVAILABLE,
        FailureCode.TIMEOUT,
    }
    return FailureEnvelope(
        code=code,
        message=messages[code],
        request_id=request_id,
        retryable=retryable,
        retry_after_seconds=retry_after_seconds if retryable else None,
    )


class CorrelationContext(BaseModel):
    """Server-derived tenant and actor context for internal workflow correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)

    @classmethod
    def from_principal(
        cls,
        principal: Principal,
        *,
        request_id: str,
        correlation_id: str | None = None,
    ) -> "CorrelationContext":
        if correlation_id is not None:
            try:
                UUID(correlation_id)
            except ValueError as exc:
                raise ValueError("correlation ID must be a UUID") from exc
        return cls(
            correlation_id=correlation_id or str(uuid4()),
            request_id=request_id,
            tenant_id=principal.tenant_id,
            actor=principal.username,
        )


class DomainEvent(BaseModel):
    """Tenant-scoped, scalar-only domain event envelope for synchronous handoff."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^\d+\.\d+$")
    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=128)
    event_type: str = Field(min_length=3, max_length=128, pattern=r"^[a-z][a-z0-9_.-]+$")
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    payload: dict[str, str | int | float | bool | None] = Field(default_factory=dict, max_length=32)

    @model_validator(mode="after")
    def validate_payload(self) -> "DomainEvent":
        forbidden = {"command", "credential", "password", "raw", "secret", "token"}
        if any(key.lower() in forbidden for key in self.payload):
            raise ValueError("domain event payload contains a forbidden field")
        if self.occurred_at.tzinfo is None:
            raise ValueError("domain event timestamp must be timezone-aware")
        return self


class HealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    NOT_READY = "not_ready"
    UNKNOWN = "unknown"


class HealthCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: HealthStatus
    latency_ms: float | None = Field(default=None, ge=0, le=30_000)
    detail: str | None = Field(default=None, max_length=256)


class HealthContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: HealthStatus = HealthStatus.OK
    service: str = Field(min_length=1, max_length=128)
    release: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    dry_run_default: bool = True


class LivenessContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["live"] = "live"
    service: str = Field(min_length=1, max_length=128)


class ReadinessContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ready", "not_ready"] = "ready"
    service: str = Field(min_length=1, max_length=128)
    checks: dict[str, HealthCheck] = Field(default_factory=dict, max_length=32)

    @model_validator(mode="after")
    def validate_status(self) -> "ReadinessContract":
        if self.status == "ready" and any(check.status != HealthStatus.OK for check in self.checks.values()):
            raise ValueError("ready status requires all checks to be ok")
        return self


class IdempotencyState(StrEnum):
    ACQUIRED = "acquired"
    REPLAY = "replay"
    IN_PROGRESS = "in_progress"
    CONFLICT = "conflict"


class IdempotencyKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str = Field(min_length=8, max_length=MAX_IDEMPOTENCY_KEY_LENGTH, pattern=r"^[A-Za-z0-9._:-]+$")


T = TypeVar("T")


class IdempotencyClaim(Generic[T]):
    def __init__(self, state: IdempotencyState, *, result: T | None = None) -> None:
        self.state = state
        self.result = result


@dataclass
class _IdempotencyRecord:
    fingerprint: str
    expires_at: float
    result: Any | None = None


class IdempotencyStore(Generic[T]):
    """Bounded thread-safe claim store for one process; it never starts a worker or queue."""

    def __init__(
        self,
        *,
        max_entries: int = MAX_IDEMPOTENCY_ENTRIES,
        ttl_seconds: int = 300,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if max_entries < 1 or max_entries > MAX_IDEMPOTENCY_ENTRIES:
            raise ValueError("idempotency store size is outside the safe bound")
        if ttl_seconds < 1 or ttl_seconds > MAX_IDEMPOTENCY_TTL_SECONDS:
            raise ValueError("idempotency TTL is outside the safe bound")
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._records: dict[tuple[str, str, str], _IdempotencyRecord] = {}
        self._lock = threading.Lock()

    def claim(self, *, tenant_id: str, actor: str, key: IdempotencyKey, fingerprint: str) -> IdempotencyClaim[T]:
        record_key = (tenant_id, actor, key.value)
        with self._lock:
            self._purge_expired()
            existing = self._records.get(record_key)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    return IdempotencyClaim(IdempotencyState.CONFLICT)
                if existing.result is None:
                    return IdempotencyClaim(IdempotencyState.IN_PROGRESS)
                return IdempotencyClaim(IdempotencyState.REPLAY, result=existing.result)
            if len(self._records) >= self.max_entries:
                self._evict_oldest()
            self._records[record_key] = _IdempotencyRecord(
                fingerprint=fingerprint,
                expires_at=self._clock() + self.ttl_seconds,
            )
            return IdempotencyClaim(IdempotencyState.ACQUIRED)

    def claim_for_principal(
        self,
        principal: Principal,
        *,
        key: IdempotencyKey,
        fingerprint: str,
    ) -> IdempotencyClaim[T]:
        return self.claim(
            tenant_id=principal.tenant_id,
            actor=principal.username,
            key=key,
            fingerprint=fingerprint,
        )

    def complete(self, *, tenant_id: str, actor: str, key: IdempotencyKey, fingerprint: str, result: T) -> None:
        record_key = (tenant_id, actor, key.value)
        with self._lock:
            record = self._records.get(record_key)
            if record is None or record.fingerprint != fingerprint:
                raise ValueError("idempotency claim is missing or conflicts")
            record.result = result
            record.expires_at = self._clock() + self.ttl_seconds

    def complete_for_principal(
        self,
        principal: Principal,
        *,
        key: IdempotencyKey,
        fingerprint: str,
        result: T,
    ) -> None:
        self.complete(
            tenant_id=principal.tenant_id,
            actor=principal.username,
            key=key,
            fingerprint=fingerprint,
            result=result,
        )

    def abandon(self, *, tenant_id: str, actor: str, key: IdempotencyKey, fingerprint: str) -> None:
        record_key = (tenant_id, actor, key.value)
        with self._lock:
            record = self._records.get(record_key)
            if record is not None and record.fingerprint == fingerprint:
                del self._records[record_key]

    def abandon_for_principal(
        self,
        principal: Principal,
        *,
        key: IdempotencyKey,
        fingerprint: str,
    ) -> None:
        self.abandon(
            tenant_id=principal.tenant_id,
            actor=principal.username,
            key=key,
            fingerprint=fingerprint,
        )

    @staticmethod
    def fingerprint(payload: Any) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [key for key, record in self._records.items() if record.expires_at <= now]
        for key in expired:
            del self._records[key]

    def _evict_oldest(self) -> None:
        oldest = min(self._records, key=lambda key: self._records[key].expires_at)
        del self._records[oldest]


__all__ = [
    "CorrelationContext",
    "DomainEvent",
    "FailureCode",
    "FailureEnvelope",
    "HealthCheck",
    "HealthContract",
    "HealthStatus",
    "IdempotencyClaim",
    "IdempotencyKey",
    "IdempotencyState",
    "IdempotencyStore",
    "LivenessContract",
    "ReadinessContract",
    "RetryDecision",
    "RetryPolicy",
    "failure_from_code",
]
