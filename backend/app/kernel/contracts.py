from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.contracts import FindingInput

SCHEMA_VERSION = "1.0"


class IntegrationContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    targets: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    dry_run: bool = True


class IntegrationAnalysisRequest(IntegrationContextRequest):
    observations: list[dict[str, Any]] = Field(default_factory=list, max_length=256)


class IntegrationContext(BaseModel):
    """Tenant-scoped, immutable-at-boundary context passed to integrations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    targets: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    dry_run: bool = True

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for target in values:
            if not target or len(target) > 255:
                raise ValueError("targets must be non-empty and at most 255 characters")
            if any(character in target for character in ("\n", "\r", "\x00")):
                raise ValueError("targets must not contain control characters")
        return values


class PlannedAction(BaseModel):
    """A declarative, non-shell action. The kernel never accepts raw command text."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1, max_length=128)
    operation: Literal["collect", "analyze", "export"]
    description: str = Field(min_length=1, max_length=1000)
    targets: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    required_permissions: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    read_only: bool = True
    dry_run: bool = True


class IntegrationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    plugin_id: str = Field(min_length=3, max_length=64)
    plugin_version: str = Field(min_length=1, max_length=32)
    request_id: str = Field(min_length=1, max_length=128)
    dry_run: bool = True
    actions: list[PlannedAction] = Field(default_factory=list, max_length=64)
    warnings: list[str] = Field(default_factory=list, max_length=32)


class NormalizedObservation(BaseModel):
    """Bounded, tenant-tagged observation input for analyzers."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    observation_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attributes: dict[str, Any] = Field(default_factory=dict, max_length=64)


class IntegrationAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    plugin_id: str = Field(min_length=3, max_length=64)
    plugin_version: str = Field(min_length=1, max_length=32)
    request_id: str = Field(min_length=1, max_length=128)
    findings: list[FindingInput] = Field(default_factory=list, max_length=256)
    warnings: list[str] = Field(default_factory=list, max_length=32)
    observation_count: int = Field(ge=0)
