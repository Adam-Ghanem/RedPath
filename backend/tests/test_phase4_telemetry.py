from datetime import datetime, timedelta, timezone

from app.core.observability import MetricsRegistry
from app.db.models import (
    TelemetryEvent,
    TelemetryIngestionRun,
    create_session_factory,
    run_alembic_downgrade,
    run_alembic_migrations,
)
from app.models.telemetry import TelemetryDetectionRequest
from app.services.detection_framework import DetectionRuleCatalog
from app.services.telemetry_correlation import evaluate_telemetry
from app.services.telemetry_resilience import TelemetryResilienceStore
from sqlalchemy import inspect as sqlalchemy_inspect


def test_source_isolated_circuit_and_capacity_budget(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'source-state.db'}")
    store = TelemetryResilienceStore(
        session_factory,
        circuit_failure_threshold=2,
        circuit_cooldown_seconds=30,
        capacity_window_seconds=20,
        capacity_max_events=2,
        capacity_max_bytes=4096,
    )
    now = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)

    assert store.try_start(
        tenant_id="lab", source="wazuh", requested_events=2, requested_bytes=4096, now=now
    )
    assert not store.try_start(
        tenant_id="lab", source="wazuh", requested_events=1, requested_bytes=1024, now=now
    )
    store.record_failure(tenant_id="lab", source="wazuh", error_code="connector_error", now=now)
    store.record_failure(
        tenant_id="lab",
        source="wazuh",
        error_code="connector_error",
        now=now + timedelta(seconds=1),
    )

    assert not store.try_start(tenant_id="lab", source="wazuh", now=now + timedelta(seconds=2))
    assert store.health(tenant_id="lab", source="wazuh", now=now + timedelta(seconds=2)).circuit_state == "open"
    assert store.try_start(tenant_id="lab", source="fixture", now=now + timedelta(seconds=2))
    assert store.try_start(tenant_id="lab", source="wazuh", now=now + timedelta(seconds=31))


def test_freshness_slo_and_drift_guidance_are_bounded_and_source_scoped(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'health.db'}")
    metrics = MetricsRegistry()
    store = TelemetryResilienceStore(
        session_factory,
        metrics=metrics,
        freshness_slo_target_seconds=900,
    )
    now = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
    store.mark_success(
        tenant_id="lab",
        source="fixture",
        checkpoint_cursor=None,
        schema_version="fixture-v1",
        last_event_at=now - timedelta(seconds=901),
        now=now,
    )
    store.record_failure(
        tenant_id="lab",
        source="fixture",
        error_code="schema_drift",
        schema_version="unknown",
        schema_signature="safe-signature",
        now=now,
    )

    health = store.health(tenant_id="lab", source="fixture", now=now)
    assert health.freshness_slo_met is False
    assert health.schema_drift_guidance == "review_provider_schema_contract"
    assert store.health(tenant_id="lab", source="wazuh", now=now).status == "unknown"
    assert "tenant_id" not in metrics.prometheus()


def test_correlation_fan_in_is_bounded_and_replay_safe(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'fan-in.db'}")
    observed_at = datetime(2026, 8, 14, 11, tzinfo=timezone.utc)
    with session_factory() as session:
        session.add(
            TelemetryIngestionRun(
                id="run-fan-in",
                tenant_id="lab",
                source="wazuh",
                start_at=observed_at - timedelta(hours=1),
                end_at=observed_at,
                fetched_count=1,
                stored_count=1,
            )
        )
        session.add(
            TelemetryEvent(
                id="event-fan-in",
                ingestion_run_id="run-fan-in",
                tenant_id="lab",
                source="wazuh",
                observed_at=observed_at,
                severity="high",
                rule_id="100001",
                rule_description="T1558.003 test event",
                asset_id="wazuh-agent:007",
                technique_ids=["T1558.003"],
                summary="bounded test event",
                safe_fields={"agent_id": "007"},
                correlation_fields={"event_id": "4769"},
                raw_sha256="a" * 64,
            )
        )
        session.commit()

    request = TelemetryDetectionRequest(
        start=observed_at - timedelta(hours=1),
        end=observed_at + timedelta(minutes=1),
        limit=1000,
    )
    response = evaluate_telemetry(
        session_factory,
        tenant_id="lab",
        request=request,
        catalog=DetectionRuleCatalog(),
        max_fan_in=1,
    )
    assert response.fan_in_limit == 1
    assert response.fan_in_truncated is True
    assert response.event_count == 1
    assert response.event_ids == ["event-fan-in"]


def test_phase4_alembic_upgrade_and_downgrade_is_additive(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'alembic.db'}"
    run_alembic_migrations(database_url)
    session_factory = create_session_factory(database_url)
    engine = session_factory.kw["bind"] if hasattr(session_factory, "kw") else None
    assert engine is not None
    columns = {column["name"] for column in sqlalchemy_inspect(engine).get_columns("telemetry_ingestion_state")}
    assert {"circuit_state", "capacity_events_reserved", "last_attempt_at"}.issubset(columns)

    run_alembic_downgrade(database_url, "22d614b2aac8")
    downgraded_columns = {
        column["name"] for column in sqlalchemy_inspect(engine).get_columns("telemetry_ingestion_state")
    }
    assert "circuit_state" not in downgraded_columns
    assert "telemetry_dead_letters" in sqlalchemy_inspect(engine).get_table_names()
