from __future__ import annotations

from dataclasses import dataclass

from app.kernel.contracts import IntegrationContext, ModuleKind
from app.plugins.base import PluginManifest
from app.plugins.registry import RegistryPlugin


@dataclass(frozen=True)
class KernelModuleFixture:
    """Synthetic module fixture containing only normalized, read-only test inputs."""

    plugin_id: str
    name: str
    module_kind: ModuleKind
    capability: str
    required_scope: str
    observation_kind: str

    def plugin(self) -> RegistryPlugin:
        return RegistryPlugin(
            PluginManifest(
                plugin_id=self.plugin_id,
                name=self.name,
                version="1.0.0",
                capabilities=(self.capability,),
                module_kind=self.module_kind,
                required_scopes=(self.required_scope,),
                supported_contract_versions=("1.0",),
                supports_dry_run=True,
                read_only=True,
            )
        )

    def observation(self, tenant_id: str = "tenant-a") -> dict[str, object]:
        return {
            "observation_id": f"{self.plugin_id}:observation",
            "tenant_id": tenant_id,
            "source": self.plugin_id,
            "kind": self.observation_kind,
            "attributes": {"evidence_ref": f"fixture:{self.plugin_id}"},
        }


KERNEL_MODULE_FIXTURES: tuple[KernelModuleFixture, ...] = (
    KernelModuleFixture(
        plugin_id="pcap.offline_analysis",
        name="Offline PCAP analysis fixture",
        module_kind=ModuleKind.PCAP,
        capability="pcap.analyze_offline",
        required_scope="evidence.read",
        observation_kind="flow_summary",
    ),
    KernelModuleFixture(
        plugin_id="telemetry.read_only",
        name="Read-only telemetry fixture",
        module_kind=ModuleKind.TELEMETRY,
        capability="telemetry.read_alerts",
        required_scope="telemetry.read",
        observation_kind="alert_summary",
    ),
    KernelModuleFixture(
        plugin_id="discovery.safe_inventory",
        name="Safe discovery fixture",
        module_kind=ModuleKind.DISCOVERY,
        capability="discovery.inventory",
        required_scope="asset.read",
        observation_kind="asset_summary",
    ),
    KernelModuleFixture(
        plugin_id="detection.observation_rules",
        name="Detection rules fixture",
        module_kind=ModuleKind.DETECTION,
        capability="detection.analyze",
        required_scope="evidence.read",
        observation_kind="detection_observation",
    ),
    KernelModuleFixture(
        plugin_id="graph.exposure_risk",
        name="Graph risk fixture",
        module_kind=ModuleKind.GRAPH,
        capability="graph.evaluate_risk",
        required_scope="graph.read",
        observation_kind="relationship_summary",
    ),
    KernelModuleFixture(
        plugin_id="case.evidence_linking",
        name="Case evidence fixture",
        module_kind=ModuleKind.CASE,
        capability="case.link_evidence",
        required_scope="case.read",
        observation_kind="finding_summary",
    ),
)


def fixture_registry():
    from app.plugins.registry import PluginRegistry

    return PluginRegistry(fixture.plugin() for fixture in KERNEL_MODULE_FIXTURES)


def fixture_context(fixture: KernelModuleFixture) -> IntegrationContext:
    return IntegrationContext(
        tenant_id="tenant-a",
        actor="server-derived-analyst",
        request_id=f"request:{fixture.plugin_id}",
        contract_version="1.0",
        requested_capabilities=(fixture.capability,),
        targets=(),
        dry_run=True,
    )


__all__ = ["KERNEL_MODULE_FIXTURES", "KernelModuleFixture", "fixture_context", "fixture_registry"]
