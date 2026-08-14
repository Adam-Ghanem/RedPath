from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from app.core.request_context import Principal
from app.platform.reliability import (
    CorrelationContext,
    DomainEvent,
    FailureCode,
    FailureEnvelope,
    HealthCheck,
    HealthContract,
    HealthStatus,
    IdempotencyKey,
    IdempotencyState,
    IdempotencyStore,
    LivenessContract,
    ReadinessContract,
    RetryPolicy,
    failure_from_code,
)
from pydantic import ValidationError


def _principal(*, tenant_id: str = "tenant-a", username: str = "analyst@example.test") -> Principal:
    return Principal(
        user_id="user-1",
        username=username,
        tenant_id=tenant_id,
        tenant_slug=tenant_id,
        roles=("analyst",),
        session_version=1,
        permissions=("read", "analyze"),
    )


def test_retry_policy_is_deterministic_and_bounded() -> None:
    policy = RetryPolicy(max_attempts=5, initial_delay_seconds=2, multiplier=2, max_delay_seconds=5)

    assert [policy.delay_for(attempt) for attempt in range(1, 6)] == [2, 4, 5, 5, 5]
    assert policy.should_retry(attempt=1, failure_code=FailureCode.TIMEOUT) is True
    assert policy.should_retry(attempt=5, failure_code=FailureCode.TIMEOUT) is False
    assert policy.should_retry(attempt=1, failure_code=FailureCode.VALIDATION_FAILED) is False


def test_failure_taxonomy_is_safe_and_retry_hints_are_consistent() -> None:
    failure = failure_from_code(
        FailureCode.DEPENDENCY_UNAVAILABLE,
        request_id="request-1",
        retry_after_seconds=3,
    )
    assert failure.retryable is True
    assert failure.retry_after_seconds == 3
    assert "exception" not in failure.message.lower()
    assert "payload" not in failure.model_dump_json().lower()

    safe_non_retryable = failure_from_code(
        FailureCode.INVALID_REQUEST,
        request_id="request-2",
        retry_after_seconds=3,
    )
    assert safe_non_retryable.retryable is False
    assert safe_non_retryable.retry_after_seconds is None

    with pytest.raises(ValidationError):
        FailureEnvelope(
            code=FailureCode.INVALID_REQUEST,
            message="invalid",
            request_id="request-2",
            retry_after_seconds=3,
        )


def test_correlation_and_event_context_are_server_derived_and_scalar_only() -> None:
    context = CorrelationContext.from_principal(_principal(), request_id="request-3")
    assert context.tenant_id == "tenant-a"
    assert context.actor == "analyst@example.test"
    event = DomainEvent(
        event_type="workflow.completed",
        correlation_id=context.correlation_id,
        request_id=context.request_id,
        tenant_id=context.tenant_id,
        actor=context.actor,
        payload={"status": "complete", "attempt": 1},
    )
    assert event.tenant_id == context.tenant_id
    assert event.actor == context.actor

    with pytest.raises(ValidationError):
        DomainEvent(
            event_type="workflow.completed",
            correlation_id=context.correlation_id,
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            actor=context.actor,
            payload={"token": "not-allowed"},
        )

    with pytest.raises(ValueError, match="correlation ID must be a UUID"):
        CorrelationContext.from_principal(_principal(), request_id="request-4", correlation_id="client-value")


def test_health_contracts_preserve_public_status_values() -> None:
    health = HealthContract(service="redpath", release="test", environment="test")
    liveness = LivenessContract(service="redpath")
    readiness = ReadinessContract(
        service="redpath",
        checks={"application": HealthCheck(status=HealthStatus.OK)},
    )

    assert health.status is HealthStatus.OK
    assert liveness.status == "live"
    assert readiness.status == "ready"


def test_readiness_contract_rejects_false_ready_state() -> None:
    with pytest.raises(ValidationError):
        ReadinessContract(
            status=HealthStatus.OK,
            service="redpath",
            checks={"database": HealthCheck(status=HealthStatus.DEGRADED)},
        )


def test_idempotency_claims_are_tenant_actor_scoped_and_concurrency_safe() -> None:
    store: IdempotencyStore[dict[str, str]] = IdempotencyStore(max_entries=32, ttl_seconds=60)
    key = IdempotencyKey(value="workflow-key-001")
    fingerprint = store.fingerprint({"operation": "case.link", "evidence_id": "evidence-1"})

    principal = _principal()

    def claim_once() -> IdempotencyState:
        return store.claim_for_principal(
            principal,
            key=key,
            fingerprint=fingerprint,
        ).state

    with ThreadPoolExecutor(max_workers=16) as executor:
        states = list(executor.map(lambda _index: claim_once(), range(16)))

    assert states.count(IdempotencyState.ACQUIRED) == 1
    assert states.count(IdempotencyState.IN_PROGRESS) == 15

    store.complete_for_principal(
        principal,
        key=key,
        fingerprint=fingerprint,
        result={"status": "complete"},
    )
    replay = store.claim_for_principal(
        principal,
        key=key,
        fingerprint=fingerprint,
    )
    assert replay.state is IdempotencyState.REPLAY
    assert replay.result == {"status": "complete"}

    conflict = store.claim_for_principal(
        principal,
        key=key,
        fingerprint=store.fingerprint({"operation": "different"}),
    )
    assert conflict.state is IdempotencyState.CONFLICT

    isolated = store.claim(
        tenant_id="tenant-b",
        actor="analyst@example.test",
        key=key,
        fingerprint=fingerprint,
    )
    assert isolated.state is IdempotencyState.ACQUIRED
