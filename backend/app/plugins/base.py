from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.kernel.contracts import (
    SCHEMA_VERSION,
    CapabilityDescriptor,
    IntegrationAnalysis,
    IntegrationContext,
    IntegrationPlan,
    ModuleKind,
    NormalizedObservation,
    PlannedAction,
)
from app.schemas.contracts import FindingInput


@dataclass(frozen=True)
class PluginManifest:
    """Stable plugin metadata exposed to the control plane."""

    plugin_id: str
    name: str
    version: str
    capabilities: tuple[str, ...]
    mitre_techniques: tuple[str, ...] = ()
    required_scopes: tuple[str, ...] = ()
    supports_dry_run: bool = True
    read_only: bool = True
    module_kind: ModuleKind = ModuleKind.DETECTION
    supported_contract_versions: tuple[str, ...] = (SCHEMA_VERSION,)
    capability_descriptors: tuple[CapabilityDescriptor, ...] = ()

    def __post_init__(self) -> None:
        if not self.plugin_id.strip():
            raise ValueError("plugin_id must not be empty")
        if not self.name.strip():
            raise ValueError("plugin name must not be empty")
        if not self.version.strip():
            raise ValueError("plugin version must not be empty")
        if not self.capabilities or any(not capability.strip() for capability in self.capabilities):
            raise ValueError("plugin capabilities must not be empty")
        if not self.supported_contract_versions:
            raise ValueError("plugin must support at least one contract version")

    def negotiated_capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        """Return explicit descriptors or safe descriptors derived from metadata."""

        if self.capability_descriptors:
            return self.capability_descriptors
        return tuple(
            CapabilityDescriptor(
                capability_id=capability,
                module_kind=self.module_kind,
                contract_versions=self.supported_contract_versions,
                required_permissions=self.required_scopes,
                read_only=True,
                supports_dry_run=True,
            )
            for capability in self.capabilities
        )


class RedPathPlugin(Protocol):
    manifest: PluginManifest

    def plan(self, context: IntegrationContext) -> IntegrationPlan:
        """Return declarative actions without executing external work."""
        ...

    def analyze(self, context: IntegrationContext, observations: list[dict]) -> IntegrationAnalysis:
        """Analyze normalized observation payloads and return typed findings."""
        ...


class DetectionPlugin(RedPathPlugin, Protocol):
    """Typed detection contract for read-only observation-to-finding plugins."""

    def detect(
        self,
        context: IntegrationContext,
        observations: list[NormalizedObservation],
    ) -> list[FindingInput]:
        """Evaluate normalized observations without executing external actions."""
        ...


class DetectionPluginBase:
    """Safe adapter that enforces the common detection plugin lifecycle."""

    manifest: PluginManifest

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        manifest = getattr(cls, "manifest", None)
        if manifest is not None and manifest.module_kind != ModuleKind.DETECTION:
            raise TypeError("DetectionPluginBase requires a detection manifest")

    def plan(self, context: IntegrationContext) -> IntegrationPlan:
        return IntegrationPlan(
            plugin_id=self.manifest.plugin_id,
            plugin_version=self.manifest.version,
            request_id=context.request_id,
            dry_run=context.dry_run,
            actions=[
                PlannedAction(
                    action_id=f"{self.manifest.plugin_id}:analyze",
                    operation="analyze",
                    description=f"Analyze normalized observations with {self.manifest.name}.",
                    targets=context.targets,
                    required_permissions=self.manifest.required_scopes,
                    read_only=True,
                    dry_run=True,
                )
            ],
            warnings=["Detection plugins analyze supplied observations only; no external work is executed."],
        )

    def analyze(self, context: IntegrationContext, observations: list[dict]) -> IntegrationAnalysis:
        normalized = [NormalizedObservation.model_validate(item) for item in observations[:256]]
        findings = self.detect(context, normalized)[:256]
        return IntegrationAnalysis(
            plugin_id=self.manifest.plugin_id,
            plugin_version=self.manifest.version,
            request_id=context.request_id,
            findings=findings,
            observation_count=len(normalized),
        )

    def detect(
        self,
        context: IntegrationContext,
        observations: list[NormalizedObservation],
    ) -> list[FindingInput]:
        raise NotImplementedError
