from collections.abc import Callable, Mapping
from typing import Any

from app.kernel.contracts import IntegrationAnalysis, IntegrationContext, IntegrationPlan, NormalizedObservation
from app.plugins.base import RedPathPlugin
from app.plugins.registry import DEFAULT_REGISTRY, PluginRegistry

ScopeValidator = Callable[[tuple[str, ...]], None]
AuditRecorder = Callable[[str, Mapping[str, Any]], object]


class IntegrationKernel:
    """Control-plane boundary for safe, typed integration planning and analysis."""

    def __init__(
        self,
        registry: PluginRegistry = DEFAULT_REGISTRY,
        scope_validator: ScopeValidator | None = None,
        audit_recorder: AuditRecorder | None = None,
    ) -> None:
        self.registry = registry
        self.scope_validator = scope_validator
        self.audit_recorder = audit_recorder

    def _plugin(self, plugin_id: str) -> RedPathPlugin:
        return self.registry.get(plugin_id)

    def _validate_context(self, plugin: RedPathPlugin, context: IntegrationContext) -> None:
        if not context.dry_run and not plugin.manifest.supports_dry_run:
            raise ValueError(f"plugin does not support the requested execution mode: {plugin.manifest.plugin_id}")
        if self.scope_validator is not None:
            self.scope_validator(context.targets)

    def plan(self, plugin_id: str, context: IntegrationContext) -> IntegrationPlan:
        plugin = self._plugin(plugin_id)
        self._validate_context(plugin, context)
        result = plugin.plan(context)
        self._record(
            "integration.plan_created",
            {
                "plugin_id": plugin.manifest.plugin_id,
                "request_id": context.request_id,
                "tenant_id": context.tenant_id,
                "actor": context.actor,
                "dry_run": context.dry_run,
                "action_count": len(result.actions),
            },
        )
        return result

    def analyze(
        self,
        plugin_id: str,
        context: IntegrationContext,
        observations: list[dict[str, Any]],
    ) -> IntegrationAnalysis:
        plugin = self._plugin(plugin_id)
        self._validate_context(plugin, context)
        if len(observations) > 256:
            raise ValueError("at most 256 observations may be submitted per analysis")
        normalized = [NormalizedObservation.model_validate(item) for item in observations]
        for observation in normalized:
            if observation.tenant_id != context.tenant_id:
                raise ValueError("observation tenant_id must match the integration context")
        result = plugin.analyze(context, [observation.model_dump(mode="json") for observation in normalized])
        self._record(
            "integration.analysis_completed",
            {
                "plugin_id": plugin.manifest.plugin_id,
                "request_id": context.request_id,
                "tenant_id": context.tenant_id,
                "actor": context.actor,
                "dry_run": context.dry_run,
                "observation_count": result.observation_count,
                "finding_count": len(result.findings),
            },
        )
        return result

    def _record(self, operation: str, details: Mapping[str, Any]) -> None:
        if self.audit_recorder is not None:
            self.audit_recorder(operation, details)
