from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.contracts import FindingInput

SCHEMA_VERSION = "1.0"
SUPPORTED_CONTRACT_VERSIONS: tuple[str, ...] = (SCHEMA_VERSION,)


class ModuleKind(StrEnum):
    """Defensive integration domains supported by the extension API."""

    PCAP = "pcap"
    TELEMETRY = "telemetry"
    DISCOVERY = "discovery"
    DETECTION = "detection"
    GRAPH = "graph"
    CASE = "case"


class IntegrationErrorCode(StrEnum):
    """Stable, non-sensitive error codes for API and worker consumers."""

    PLUGIN_NOT_FOUND = "plugin_not_found"
    INCOMPATIBLE_CONTRACT_VERSION = "incompatible_contract_version"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    INVALID_REQUEST = "invalid_request"
    PERMISSION_DENIED = "permission_denied"
    SCOPE_VIOLATION = "scope_violation"
    TENANT_MISMATCH = "tenant_mismatch"
    DRY_RUN_REQUIRED = "dry_run_required"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"


class IntegrationError(BaseModel):
    """Structured extension error without stack traces or raw source payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    code: IntegrationErrorCode
    message: str = Field(min_length=1, max_length=500)
    request_id: str = Field(min_length=1, max_length=128)
    plugin_id: str | None = Field(default=None, min_length=3, max_length=64)
    details: dict[str, str] = Field(default_factory=dict, max_length=16)
    retryable: bool = False


class IntegrationKernelError(ValueError):
    """Safe exception carrying the stable error envelope and HTTP mapping."""

    def __init__(self, error: IntegrationError, status_code: int) -> None:
        self.error = error
        self.status_code = status_code
        super().__init__(error.message)


class IntegrationContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    contract_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$")
    requested_capabilities: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    targets: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    dry_run: bool = True


class IntegrationAnalysisRequest(IntegrationContextRequest):
    observations: list[dict[str, Any]] = Field(default_factory=list, max_length=256)


class CapabilityDescriptor(BaseModel):
    """Negotiable capability exposed by a trusted read-only integration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(min_length=3, max_length=128)
    module_kind: ModuleKind
    contract_versions: tuple[str, ...] = Field(default=(SCHEMA_VERSION,), min_length=1, max_length=8)
    required_permissions: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    read_only: Literal[True] = True
    supports_dry_run: Literal[True] = True


class CapabilityNegotiationRequest(BaseModel):
    """Client capability request; tenant and actor are always server-derived."""

    model_config = ConfigDict(extra="forbid")

    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    contract_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$")
    requested_capabilities: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    dry_run: bool = True


class CapabilityNegotiation(BaseModel):
    """Compatibility decision returned before module planning or analysis."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    plugin_id: str = Field(min_length=3, max_length=64)
    plugin_version: str = Field(min_length=1, max_length=32)
    request_id: str = Field(min_length=1, max_length=128)
    requested_contract_version: str = Field(min_length=1, max_length=16)
    selected_contract_version: str | None = Field(default=None, max_length=16)
    compatible: bool
    capabilities: tuple[CapabilityDescriptor, ...] = ()
    unsupported_capabilities: tuple[str, ...] = ()
    error: IntegrationError | None = None


class PaginationRequest(BaseModel):
    """Bounded cursor pagination request shared by extension catalog consumers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=6, pattern=r"^\d{1,6}$")


class PaginationMetadata(BaseModel):
    """Stable page metadata with an opaque-to-consumer forward cursor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    limit: int = Field(ge=1, le=100)
    next_cursor: str | None = Field(default=None, min_length=1, max_length=6, pattern=r"^\d{1,6}$")
    has_more: bool = False


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Typed pagination envelope for API and worker list responses."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    items: list[T] = Field(default_factory=list, max_length=100)
    pagination: PaginationMetadata


class PluginCatalogItem(BaseModel):
    """Safe read-only plugin catalog projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plugin_id: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=32)
    capabilities: tuple[str, ...] = ()
    capability_descriptors: tuple[CapabilityDescriptor, ...] = ()
    supported_contract_versions: tuple[str, ...] = (SCHEMA_VERSION,)
    required_scopes: tuple[str, ...] = ()
    supports_dry_run: Literal[True] = True
    read_only: Literal[True] = True


class PluginCatalogPage(Page[PluginCatalogItem]):
    """Paginated plugin catalog response."""


class IntegrationContext(BaseModel):
    """Tenant-scoped, immutable-at-boundary context passed to integrations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    contract_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$")
    requested_capabilities: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
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
    kind: str = Field(default="generic", min_length=2, max_length=128)
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


__all__ = [
    "CapabilityDescriptor",
    "CapabilityNegotiation",
    "CapabilityNegotiationRequest",
    "IntegrationAnalysis",
    "IntegrationAnalysisRequest",
    "IntegrationContext",
    "IntegrationContextRequest",
    "IntegrationError",
    "IntegrationErrorCode",
    "IntegrationKernelError",
    "IntegrationPlan",
    "ModuleKind",
    "NormalizedObservation",
    "Page",
    "PaginationMetadata",
    "PaginationRequest",
    "PlannedAction",
    "PluginCatalogItem",
    "PluginCatalogPage",
    "SCHEMA_VERSION",
    "SUPPORTED_CONTRACT_VERSIONS",
]
