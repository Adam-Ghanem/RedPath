from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_TECHNIQUE_ID_PATTERN = r"^T\d{4}(?:\.\d{3})?$"


class TelemetryWindowQuery(BaseModel):
    """Allow-listed time and technique filters; tenant identity is server-derived."""

    model_config = ConfigDict(extra="forbid")

    start: datetime
    end: datetime
    technique_ids: list[str] = Field(default_factory=list, max_length=50)
    limit: int = Field(default=200, ge=1, le=1000)

    @field_validator("start", "end")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("telemetry query bounds must be timezone-aware")
        return value

    @field_validator("technique_ids")
    @classmethod
    def validate_technique_ids(cls, values: list[str]) -> list[str]:
        for technique_id in values:
            if len(technique_id) > 32 or not re.fullmatch(_TECHNIQUE_ID_PATTERN, technique_id):
                raise ValueError(f"invalid MITRE technique ID: {technique_id}")
        return list(dict.fromkeys(values))


class TelemetryQuery(TelemetryWindowQuery):
    """Ingestion query with a tenant claim supplied by the authenticated API layer."""

    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class TelemetryDetectionRequest(TelemetryWindowQuery):
    """Evaluate registered detection rules against persisted normalized telemetry."""

    rule_ids: list[str] = Field(default_factory=list, max_length=50)


class TelemetryEvent(BaseModel):
    """Redacted event projection safe for analyst workflows and downstream correlation."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    source: Literal["wazuh"] = "wazuh"
    observed_at: datetime
    severity: Literal["info", "low", "medium", "high", "critical"]
    rule_id: str | None = Field(default=None, max_length=64)
    rule_description: str | None = Field(default=None, max_length=1000)
    asset_id: str | None = Field(default=None, max_length=128)
    technique_ids: list[str] = Field(default_factory=list, max_length=50)
    summary: str = Field(default="", max_length=1000)
    safe_fields: dict[str, str] = Field(default_factory=dict, max_length=20)
    correlation_fields: dict[str, str | int | bool] = Field(default_factory=dict, max_length=30)
    raw_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")


class TelemetryIngestionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    tenant_id: str
    source: Literal["wazuh"] = "wazuh"
    start: datetime
    end: datetime
    fetched_count: int = Field(ge=0)
    stored_count: int = Field(ge=0)
    deduplicated_count: int = Field(ge=0)
    events: list[TelemetryEvent] = Field(default_factory=list, max_length=1000)


class TelemetryListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    events: list[TelemetryEvent] = Field(default_factory=list, max_length=1000)


class TelemetryDetectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    start: datetime
    end: datetime
    event_count: int = Field(ge=0)
    event_ids: list[str] = Field(default_factory=list, max_length=1000)
    evaluation: dict[str, Any]


class TelemetryEvidenceProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    tenant_id: str
    source: Literal["wazuh"] = "wazuh"
    observed_at: datetime
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    technique_ids: list[str] = Field(default_factory=list, max_length=50)
    asset_id: str | None = None
    rule_id: str | None = None
    raw_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")


class TelemetryHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    source: Literal["wazuh"] = "wazuh"
    status: Literal["unknown", "healthy", "degraded"]
    last_run_id: str | None = None
    last_run_at: datetime | None = None
    last_event_at: datetime | None = None
    last_fetched_count: int = Field(default=0, ge=0)
    last_stored_count: int = Field(default=0, ge=0)
    last_deduplicated_count: int = Field(default=0, ge=0)
    total_runs: int = Field(default=0, ge=0)
    total_events: int = Field(default=0, ge=0)
    total_deduplicated: int = Field(default=0, ge=0)
    lag_seconds: float | None = Field(default=None, ge=0)
    checkpoint_present: bool = False
    schema_version: str | None = Field(default=None, max_length=64)
    schema_drift_count: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    dead_letter_count: int = Field(default=0, ge=0)
    last_error_code: str | None = Field(default=None, max_length=64)


class WazuhDocument(BaseModel):
    """Internal adapter projection; raw source is never returned by the API."""

    model_config = ConfigDict(extra="allow")

    document_id: str | None = None
    source: dict[str, Any] = Field(default_factory=dict)
