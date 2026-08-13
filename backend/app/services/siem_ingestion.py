from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from app.db.models import TelemetryEvent as TelemetryEventRow
from app.db.models import TelemetryIngestionRun, utcnow
from app.models.telemetry import TelemetryEvent, TelemetryIngestionResponse, TelemetryListResponse, TelemetryQuery
from app.services.telemetry_correlation import load_telemetry
from app.services.wazuh import WazuhIndexerClient

_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)\b(?:authorization|password|passwd|secret|token|api[-_]?key)\b\s*[:=]\s*[^\s,;]+"
)
_BEARER_PATTERN = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_SAFE_FIELD_MAP = {
    ("agent", "id"): "agent_id",
    ("agent", "name"): "agent_name",
    ("location",): "location",
    ("decoder", "name"): "decoder",
    ("manager", "name"): "manager",
    ("data", "event_id"): "event_id",
    ("data", "srcuser"): "srcuser",
    ("data", "dstuser"): "dstuser",
    ("data", "host"): "host",
    ("data", "preauth_required"): "preauth_required",
    ("data", "enrollee_supplies_subject"): "enrollee_supplies_subject",
    ("data", "client_auth_eku"): "client_auth_eku",
}
_CORRELATION_FIELD_MAP = {
    ("data", "event_id"): "event_id",
    ("data", "srcuser"): "srcuser",
    ("data", "dstuser"): "dstuser",
    ("data", "host"): "host",
    ("data", "preauth_required"): "preauth_required",
    ("data", "enrollee_supplies_subject"): "enrollee_supplies_subject",
    ("data", "client_auth_eku"): "client_auth_eku",
}


def _nested(source: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = source
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _bounded_text(value: Any, length: int = 1000) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:length] if text else None


def _redacted_text(value: Any, length: int = 1000) -> str | None:
    text = _bounded_text(value, length)
    if text is None:
        return None
    text = _BEARER_PATTERN.sub("[REDACTED]", text)
    return _SECRET_VALUE_PATTERN.sub("[REDACTED]", text)


def _safe_scalar(value: Any) -> str | int | bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        bounded = value.strip()[:256]
        return bounded or None
    return None


def _correlation_fields(source: dict[str, Any]) -> dict[str, str | int | bool]:
    fields: dict[str, str | int | bool] = {}
    for path, key in _CORRELATION_FIELD_MAP.items():
        value = _safe_scalar(_nested(source, path))
        if value is not None:
            fields[key] = value
    return fields


def _parse_timestamp(source: dict[str, Any]) -> datetime:
    value = source.get("timestamp") or source.get("@timestamp")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return utcnow()


def _severity(source: dict[str, Any]) -> str:
    raw_level = _nested(source, ("rule", "level"))
    try:
        level = int(raw_level)
    except (TypeError, ValueError):
        level = 0
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def _technique_ids(source: dict[str, Any], description: str | None) -> list[str]:
    candidates: list[str] = []
    mitre = _nested(source, ("rule", "mitre"))
    if isinstance(mitre, dict):
        for key in ("id", "ids", "technique", "techniques"):
            value = mitre.get(key)
            if isinstance(value, str):
                candidates.append(value)
            elif isinstance(value, list):
                candidates.extend(str(item) for item in value)
    if description:
        candidates.extend(_TECHNIQUE_PATTERN.findall(description))
    found: list[str] = []
    for candidate in candidates:
        found.extend(_TECHNIQUE_PATTERN.findall(candidate))
    return list(dict.fromkeys(found))[:50]


def normalize_wazuh_document(document: dict[str, Any], tenant_id: str) -> TelemetryEvent:
    """Project a Wazuh document into a bounded, non-raw analyst event."""

    source = document.get("_source", document)
    if not isinstance(source, dict):
        source = {}
    raw_bytes = json.dumps(source, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_event_id = document.get("_id") or source.get("id") or raw_sha256[:32]
    event_id = hashlib.sha256(f"{tenant_id}:wazuh:{raw_event_id}".encode("utf-8")).hexdigest()
    rule_id = _bounded_text(_nested(source, ("rule", "id")), 64)
    description = _redacted_text(_nested(source, ("rule", "description")), 1000)
    agent_id = _bounded_text(_nested(source, ("agent", "id")), 128)
    safe_fields: dict[str, str | int | float | bool] = {}
    for path, key in _SAFE_FIELD_MAP.items():
        value = _safe_scalar(_nested(source, path))
        if value is not None and value != "":
            safe_fields[key] = value
    asset_id = f"wazuh-agent:{agent_id}" if agent_id else None
    return TelemetryEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        observed_at=_parse_timestamp(source),
        severity=_severity(source),
        rule_id=rule_id,
        rule_description=description,
        asset_id=asset_id,
        technique_ids=_technique_ids(source, description),
        summary=description or "Wazuh alert",
        safe_fields=safe_fields,
        correlation_fields=_correlation_fields(source),
        raw_sha256=raw_sha256,
    )


class SiemIngestionService:
    """Read-only Wazuh retrieval plus local, redacted persistence."""

    def __init__(
        self,
        client: WazuhIndexerClient,
        session_factory: Callable[[], Any],
        *,
        max_query_window_hours: int = 24,
    ) -> None:
        self.client = client
        self.session_factory = session_factory
        self.max_query_window_hours = max_query_window_hours

    async def ingest(self, query: TelemetryQuery) -> TelemetryIngestionResponse:
        start = query.start.astimezone(timezone.utc)
        end = query.end.astimezone(timezone.utc)
        if start >= end:
            raise ValueError("telemetry query start must be before end")
        window_hours = (end - start).total_seconds() / 3600
        if window_hours > self.max_query_window_hours:
            raise ValueError(f"telemetry query window cannot exceed {self.max_query_window_hours} hours")
        raw_documents = await self.client.search_alerts(
            start=start,
            end=end,
            technique_ids=query.technique_ids,
            size=query.limit,
        )
        events = [normalize_wazuh_document(document, query.tenant_id) for document in raw_documents]
        run_id = str(uuid4())
        stored_count = 0
        deduplicated_count = 0
        with self.session_factory() as session:
            session.add(
                TelemetryIngestionRun(
                    id=run_id,
                    tenant_id=query.tenant_id,
                    source="wazuh",
                    start_at=start,
                    end_at=end,
                    fetched_count=len(events),
                )
            )
            for event in events:
                existing = session.get(TelemetryEventRow, event.event_id)
                if existing is not None:
                    deduplicated_count += 1
                    continue
                session.add(
                    TelemetryEventRow(
                        id=event.event_id,
                        ingestion_run_id=run_id,
                        tenant_id=event.tenant_id,
                        source=event.source,
                        observed_at=event.observed_at,
                        severity=event.severity,
                        rule_id=event.rule_id,
                        rule_description=event.rule_description,
                        asset_id=event.asset_id,
                        technique_ids=event.technique_ids,
                        summary=event.summary,
                        safe_fields=event.safe_fields,
                        correlation_fields=event.correlation_fields,
                        raw_sha256=event.raw_sha256,
                    )
                )
                stored_count += 1
            session.flush()
            run = session.get(TelemetryIngestionRun, run_id)
            if run is None:
                raise RuntimeError("ingestion run was not persisted")
            run.stored_count = stored_count
            run.deduplicated_count = deduplicated_count
            session.commit()
        return TelemetryIngestionResponse(
            run_id=run_id,
            tenant_id=query.tenant_id,
            start=start,
            end=end,
            fetched_count=len(events),
            stored_count=stored_count,
            deduplicated_count=deduplicated_count,
            events=events,
        )


def list_telemetry(
    session_factory: Callable[[], Any],
    *,
    tenant_id: str,
    start: datetime,
    end: datetime,
    limit: int,
) -> TelemetryListResponse:
    events = load_telemetry(
        session_factory,
        tenant_id=tenant_id,
        start=start,
        end=end,
        limit=limit,
    )
    return TelemetryListResponse(tenant_id=tenant_id, events=events)
