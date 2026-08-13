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
)


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
