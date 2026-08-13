from __future__ import annotations

import re
from typing import Iterable

from app.kernel.contracts import (
    SCHEMA_VERSION,
    CapabilityNegotiation,
    CapabilityNegotiationRequest,
    IntegrationAnalysis,
    IntegrationContext,
    IntegrationError,
    IntegrationErrorCode,
    IntegrationPlan,
    ModuleKind,
    NormalizedObservation,
    PaginationMetadata,
    PaginationRequest,
    PlannedAction,
    PluginCatalogItem,
    PluginCatalogPage,
)
from app.plugins.base import PluginManifest, RedPathPlugin

_PLUGIN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")


class RegistryPlugin:
    """Safe built-in adapter used until a domain module supplies its analyzer."""

    def __init__(self, manifest: PluginManifest) -> None:
        self.manifest = manifest

    def plan(self, context: IntegrationContext) -> IntegrationPlan:
        operation = "analyze" if "detection" in self.manifest.capabilities else "collect"
        return IntegrationPlan(
            plugin_id=self.manifest.plugin_id,
            plugin_version=self.manifest.version,
            request_id=context.request_id,
            dry_run=context.dry_run,
            actions=[
                PlannedAction(
                    action_id=f"{self.manifest.plugin_id}:plan",
                    operation=operation,
                    description=f"Prepare {self.manifest.name} within the authorized integration boundary.",
                    targets=context.targets,
                    required_permissions=self.manifest.required_scopes,
                    read_only=self.manifest.read_only,
                    dry_run=context.dry_run,
                )
            ],
            warnings=(
                ["This registry adapter only plans work; domain execution remains outside the kernel."]
                if context.dry_run
                else ["Execution is not implemented by the registry adapter; no external work was performed."]
            ),
        )

    def analyze(self, context: IntegrationContext, observations: list[dict]) -> IntegrationAnalysis:
        normalized = [NormalizedObservation.model_validate(item) for item in observations]
        return IntegrationAnalysis(
            plugin_id=self.manifest.plugin_id,
            plugin_version=self.manifest.version,
            request_id=context.request_id,
            observation_count=len(normalized),
            warnings=["No domain analyzer is registered for this adapter; observations were not transformed."],
        )


BUILTIN_PLUGINS: tuple[PluginManifest, ...] = (
    PluginManifest(
        plugin_id="recon.safe_inventory",
        name="Safe service inventory",
        version="0.1.0",
        capabilities=("recon", "asset_discovery"),
        module_kind=ModuleKind.DISCOVERY,
        mitre_techniques=(),
        required_scopes=("asset.read",),
        supports_dry_run=True,
        read_only=True,
        supported_contract_versions=(SCHEMA_VERSION,),
    ),
    PluginManifest(
        plugin_id="ad.observation_analyzer",
        name="AD observation analyzer",
        version="0.1.0",
        capabilities=("detection", "finding_correlation"),
        module_kind=ModuleKind.DETECTION,
        mitre_techniques=("T1558.003", "T1558.004", "T1649"),
        required_scopes=("evidence.read",),
        supports_dry_run=True,
        read_only=True,
        supported_contract_versions=(SCHEMA_VERSION,),
    ),
    PluginManifest(
        plugin_id="purple.wazuh_gap_report",
        name="Wazuh detection-gap report",
        version="0.1.0",
        capabilities=("purple_team", "siem_validation"),
        module_kind=ModuleKind.TELEMETRY,
        mitre_techniques=("T1558.003", "T1558.004", "T1649"),
        required_scopes=("telemetry.read",),
        supports_dry_run=True,
        read_only=True,
        supported_contract_versions=(SCHEMA_VERSION,),
    ),
)


class PluginRegistry:
    """Validated registry that prevents ambiguous or unsafe plugin metadata."""

    def __init__(self, plugins: Iterable[RedPathPlugin] = ()) -> None:
        self._plugins: dict[str, RedPathPlugin] = {}
        for plugin in plugins:
            self.register(plugin)

    def register(self, plugin: RedPathPlugin) -> None:
        manifest = plugin.manifest
        if not _PLUGIN_ID.fullmatch(manifest.plugin_id):
            raise ValueError("plugin_id must use lowercase letters, digits, '.', '_' or '-'")
        if not manifest.capabilities or any(not item for item in manifest.capabilities):
            raise ValueError("plugin capabilities must not be empty")
        if not manifest.read_only:
            raise ValueError("kernel plugins must be read-only")
        if not manifest.supports_dry_run:
            raise ValueError("kernel plugins must support dry-run")
        if not manifest.supported_contract_versions:
            raise ValueError("kernel plugins must declare supported contract versions")
        if manifest.plugin_id in self._plugins:
            raise ValueError(f"plugin already registered: {manifest.plugin_id}")
        self._plugins[manifest.plugin_id] = plugin

    def get(self, plugin_id: str) -> RedPathPlugin:
        try:
            return self._plugins[plugin_id]
        except KeyError as exc:
            raise KeyError(f"unknown plugin: {plugin_id}") from exc

    def manifests(self) -> list[PluginManifest]:
        return [self._plugins[key].manifest for key in sorted(self._plugins)]

    def negotiate(self, plugin_id: str, request: CapabilityNegotiationRequest) -> CapabilityNegotiation:
        try:
            manifest = self.get(plugin_id).manifest
        except KeyError:
            error = IntegrationError(
                code=IntegrationErrorCode.PLUGIN_NOT_FOUND,
                message="requested integration plugin is not registered",
                request_id=request.request_id or "negotiation",
                plugin_id=plugin_id,
            )
            return CapabilityNegotiation(
                plugin_id=plugin_id,
                plugin_version="unknown",
                request_id=request.request_id or "negotiation",
                requested_contract_version=request.contract_version,
                compatible=False,
                error=error,
            )

        request_id = request.request_id or "negotiation"
        if request.contract_version not in manifest.supported_contract_versions:
            error = IntegrationError(
                code=IntegrationErrorCode.INCOMPATIBLE_CONTRACT_VERSION,
                message="integration contract version is not supported by this plugin",
                request_id=request_id,
                plugin_id=plugin_id,
                details={"supported_versions": ",".join(manifest.supported_contract_versions)},
            )
            return CapabilityNegotiation(
                plugin_id=plugin_id,
                plugin_version=manifest.version,
                request_id=request_id,
                requested_contract_version=request.contract_version,
                compatible=False,
                capabilities=manifest.negotiated_capabilities(),
                error=error,
            )

        unsupported = tuple(
            capability for capability in request.requested_capabilities if capability not in manifest.capabilities
        )
        if unsupported:
            error = IntegrationError(
                code=IntegrationErrorCode.UNSUPPORTED_CAPABILITY,
                message="one or more requested plugin capabilities are unavailable",
                request_id=request_id,
                plugin_id=plugin_id,
                details={"unsupported_capabilities": ",".join(unsupported)},
            )
            return CapabilityNegotiation(
                plugin_id=plugin_id,
                plugin_version=manifest.version,
                request_id=request_id,
                requested_contract_version=request.contract_version,
                selected_contract_version=request.contract_version,
                compatible=False,
                capabilities=manifest.negotiated_capabilities(),
                unsupported_capabilities=unsupported,
                error=error,
            )

        return CapabilityNegotiation(
            plugin_id=plugin_id,
            plugin_version=manifest.version,
            request_id=request_id,
            requested_contract_version=request.contract_version,
            selected_contract_version=request.contract_version,
            compatible=True,
            capabilities=manifest.negotiated_capabilities(),
        )

    def catalog_page(self, request: PaginationRequest) -> PluginCatalogPage:
        manifests = self.manifests()
        start = int(request.cursor or "0")
        page_manifests = manifests[start : start + request.limit]
        next_offset = start + len(page_manifests)
        has_more = next_offset < len(manifests)
        items = [
            PluginCatalogItem(
                plugin_id=manifest.plugin_id,
                name=manifest.name,
                version=manifest.version,
                capabilities=manifest.capabilities,
                capability_descriptors=manifest.negotiated_capabilities(),
                supported_contract_versions=manifest.supported_contract_versions,
                required_scopes=manifest.required_scopes,
                supports_dry_run=True,
                read_only=True,
            )
            for manifest in page_manifests
        ]
        return PluginCatalogPage(
            items=items,
            pagination=PaginationMetadata(
                limit=request.limit,
                next_cursor=str(next_offset) if has_more else None,
                has_more=has_more,
            ),
        )


DEFAULT_REGISTRY = PluginRegistry(RegistryPlugin(manifest) for manifest in BUILTIN_PLUGINS)


def list_plugins() -> list[dict[str, object]]:
    return [
        {
            "plugin_id": manifest.plugin_id,
            "name": manifest.name,
            "version": manifest.version,
            "capabilities": list(manifest.capabilities),
            "mitre_techniques": list(manifest.mitre_techniques),
            "required_scopes": list(manifest.required_scopes),
            "supports_dry_run": manifest.supports_dry_run,
            "read_only": manifest.read_only,
            "module_kind": manifest.module_kind.value,
            "supported_contract_versions": list(manifest.supported_contract_versions),
            "capability_descriptors": [
                descriptor.model_dump(mode="json") for descriptor in manifest.negotiated_capabilities()
            ],
        }
        for manifest in DEFAULT_REGISTRY.manifests()
    ]
