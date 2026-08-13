from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from app.core.observability import MetricsRegistry
from app.db.models import TelemetryEvent as TelemetryEventRow
from app.db.models import TelemetryIngestionRun
from app.models.telemetry import (
    TelemetryDetectionRequest,
    TelemetryDetectionResponse,
    TelemetryEvent,
    TelemetryEvidenceProjection,
    TelemetryHealthResponse,
)
from app.schemas.contracts import WazuhAlert
from app.services.detection_framework import DetectionRuleCatalog
from app.services.telemetry_resilience import TelemetryResilienceStore

MAX_CORRELATION_WINDOW_HOURS = 24


def validate_window(
    start: datetime,
    end: datetime,
    *,
    max_hours: int = MAX_CORRELATION_WINDOW_HOURS,
) -> tuple[datetime, datetime]:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("telemetry query bounds must be timezone-aware")
    start_utc = start.astimezone(timezone.utc)
    end_utc = end.astimezone(timezone.utc)
    if start_utc >= end_utc:
        raise ValueError("telemetry query start must be before end")
    if end_utc - start_utc > timedelta(hours=max_hours):
        raise ValueError(f"telemetry query window cannot exceed {max_hours} hours")
    return start_utc, end_utc


def load_telemetry(
    session_factory: Callable[[], Any],
    *,
    tenant_id: str,
    start: datetime,
    end: datetime,
    limit: int,
) -> list[TelemetryEvent]:
    start_utc, end_utc = validate_window(start, end)
    bounded_limit = min(max(limit, 1), 1000)
    with session_factory() as session:
        rows = session.scalars(
            select(TelemetryEventRow)
            .where(
                TelemetryEventRow.tenant_id == tenant_id,
                TelemetryEventRow.observed_at >= start_utc,
                TelemetryEventRow.observed_at <= end_utc,
            )
            .order_by(TelemetryEventRow.observed_at.asc(), TelemetryEventRow.id.asc())
            .limit(bounded_limit)
        ).all()
    return [_row_to_event(row) for row in rows]


def evaluate_telemetry(
    session_factory: Callable[[], Any],
    *,
    tenant_id: str,
    request: TelemetryDetectionRequest,
    catalog: DetectionRuleCatalog,
    metrics: MetricsRegistry | None = None,
) -> TelemetryDetectionResponse:
    start, end = validate_window(request.start, request.end)
    events = load_telemetry(
        session_factory,
        tenant_id=tenant_id,
        start=start,
        end=end,
        limit=request.limit,
    )
    alerts = [_event_to_alert(event) for event in events]
    evaluation = catalog.evaluate(alerts, request.rule_ids)
    if metrics:
        metrics.increment_telemetry("correlation_evaluations_total")
        metrics.increment_telemetry("correlation_matches_total", len(evaluation.matches))
    return TelemetryDetectionResponse(
        tenant_id=tenant_id,
        start=start,
        end=end,
        event_count=len(events),
        event_ids=[event.event_id for event in events],
        evaluation=evaluation.model_dump(mode="json"),
    )


def project_case_evidence(events: list[TelemetryEvent]) -> list[TelemetryEvidenceProjection]:
    return [
        TelemetryEvidenceProjection(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            observed_at=event.observed_at,
            severity=event.severity,
            title=event.summary,
            technique_ids=event.technique_ids,
            asset_id=event.asset_id,
            rule_id=event.rule_id,
            raw_sha256=event.raw_sha256,
        )
        for event in events
    ]


def health_diagnostics(
    session_factory: Callable[[], Any],
    *,
    tenant_id: str,
    resilience: TelemetryResilienceStore | None = None,
    lag_warning_seconds: int = 900,
    now: datetime | None = None,
) -> TelemetryHealthResponse:
    with session_factory() as session:
        last_run = session.scalar(
            select(TelemetryIngestionRun)
            .where(TelemetryIngestionRun.tenant_id == tenant_id)
            .order_by(TelemetryIngestionRun.created_at.desc())
            .limit(1)
        )
        total_runs = session.scalar(
            select(func.count(TelemetryIngestionRun.id)).where(TelemetryIngestionRun.tenant_id == tenant_id)
        ) or 0
        total_events = session.scalar(
            select(func.coalesce(func.sum(TelemetryIngestionRun.stored_count), 0)).where(
                TelemetryIngestionRun.tenant_id == tenant_id
            )
        ) or 0
        total_deduplicated = session.scalar(
            select(func.coalesce(func.sum(TelemetryIngestionRun.deduplicated_count), 0)).where(
                TelemetryIngestionRun.tenant_id == tenant_id
            )
        ) or 0
        last_event_at = session.scalar(
            select(func.max(TelemetryEventRow.observed_at)).where(TelemetryEventRow.tenant_id == tenant_id)
        )
    resilience_health = resilience.health(tenant_id=tenant_id, now=now) if resilience else None
    status = "unknown" if last_run is None else "healthy"
    if last_run is not None and last_run.fetched_count != last_run.stored_count + last_run.deduplicated_count:
        status = "degraded"
    if resilience_health and resilience_health.status != "unknown":
        status = resilience_health.status
    lag_seconds = resilience_health.lag_seconds if resilience_health else None
    return TelemetryHealthResponse(
        tenant_id=tenant_id,
        status=status,
        last_run_id=last_run.id if last_run else None,
        last_run_at=last_run.created_at if last_run else None,
        last_event_at=last_event_at,
        last_fetched_count=last_run.fetched_count if last_run else 0,
        last_stored_count=last_run.stored_count if last_run else 0,
        last_deduplicated_count=last_run.deduplicated_count if last_run else 0,
        total_runs=int(total_runs),
        total_events=int(total_events),
        total_deduplicated=int(total_deduplicated),
        lag_seconds=lag_seconds,
        checkpoint_present=resilience_health.checkpoint_present if resilience_health else False,
        schema_version=resilience_health.schema_version if resilience_health else None,
        schema_drift_count=resilience_health.schema_drift_count if resilience_health else 0,
        consecutive_failures=resilience_health.consecutive_failures if resilience_health else 0,
        dead_letter_count=resilience_health.dead_letter_count if resilience_health else 0,
        last_error_code=resilience_health.last_error_code if resilience_health else None,
    )


def _row_to_event(row: TelemetryEventRow) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=row.id,
        tenant_id=row.tenant_id,
        source="wazuh",
        observed_at=row.observed_at,
        severity=row.severity,
        rule_id=row.rule_id,
        rule_description=row.rule_description,
        asset_id=row.asset_id,
        technique_ids=row.technique_ids or [],
        summary=row.summary,
        safe_fields=row.safe_fields or {},
        correlation_fields=row.correlation_fields or {},
        raw_sha256=row.raw_sha256,
    )


def _event_to_alert(event: TelemetryEvent) -> WazuhAlert:
    rule: dict[str, Any] = {
        "id": event.rule_id,
        "description": event.rule_description or event.summary,
        "source": event.source,
    }
    data = dict(event.correlation_fields)
    data["source"] = event.source
    return WazuhAlert(
        id=event.event_id,
        timestamp=event.observed_at.astimezone(timezone.utc).isoformat(),
        rule=rule,
        data=data,
    )


__all__ = [
    "MAX_CORRELATION_WINDOW_HOURS",
    "evaluate_telemetry",
    "health_diagnostics",
    "load_telemetry",
    "project_case_evidence",
    "validate_window",
]
