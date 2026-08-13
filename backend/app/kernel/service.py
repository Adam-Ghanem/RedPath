from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pydantic import ValidationError

from app.kernel.contracts import (
    CapabilityNegotiation,
    CapabilityNegotiationRequest,
    IntegrationAnalysis,
    IntegrationContext,
    IntegrationError,
    IntegrationErrorCode,
    IntegrationKernelError,
    IntegrationPlan,
    NormalizedObservation,
)
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

    def _plugin(self, plugin_id: str, request_id: str) -> RedPathPlugin:
        try:
            return self.registry.get(plugin_id)
        except KeyError as exc:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.PLUGIN_NOT_FOUND,
                    message="requested integration plugin is not registered",
                    request_id=request_id,
                    plugin_id=plugin_id,
                ),
                status_code=404,
            ) from exc

    def _validate_context(self, plugin: RedPathPlugin, context: IntegrationContext) -> None:
        if context.contract_version not in plugin.manifest.supported_contract_versions:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.INCOMPATIBLE_CONTRACT_VERSION,
                    message="integration contract version is not supported by this plugin",
                    request_id=context.request_id,
                    plugin_id=plugin.manifest.plugin_id,
                    details={
                        "supported_versions": ",".join(plugin.manifest.supported_contract_versions),
                    },
                ),
                status_code=422,
            )
        unsupported = tuple(
            capability
            for capability in context.requested_capabilities
            if capability not in plugin.manifest.capabilities
        )
        if unsupported:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.UNSUPPORTED_CAPABILITY,
                    message="one or more requested plugin capabilities are unavailable",
                    request_id=context.request_id,
                    plugin_id=plugin.manifest.plugin_id,
                    details={"unsupported_capabilities": ",".join(unsupported)},
                ),
                status_code=422,
            )
        if not context.dry_run and not plugin.manifest.supports_dry_run:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.DRY_RUN_REQUIRED,
                    message="integration plugin requires dry-run mode",
                    request_id=context.request_id,
                    plugin_id=plugin.manifest.plugin_id,
                ),
                status_code=422,
            )
        if self.scope_validator is not None:
            self.scope_validator(context.targets)

    def negotiate(self, plugin_id: str, context: IntegrationContext) -> CapabilityNegotiation:
        """Return a compatibility decision before a plugin operation is attempted."""

        request = CapabilityNegotiationRequest(
            request_id=context.request_id,
            contract_version=context.contract_version,
            requested_capabilities=context.requested_capabilities,
            dry_run=context.dry_run,
        )
        return self.negotiate_request(
            plugin_id,
            request,
            tenant_id=context.tenant_id,
            actor=context.actor,
        )

    def negotiate_request(
        self,
        plugin_id: str,
        request: CapabilityNegotiationRequest,
        *,
        tenant_id: str,
        actor: str,
    ) -> CapabilityNegotiation:
        """Negotiate a request before internal execution-context validation."""

        decision = self.registry.negotiate(plugin_id, request)
        self._record(
            "integration.capability_negotiated",
            {
                "plugin_id": plugin_id,
                "request_id": request.request_id or "negotiation",
                "tenant_id": tenant_id,
                "actor": actor,
                "contract_version": request.contract_version,
                "compatible": decision.compatible,
                "requested_capability_count": len(request.requested_capabilities),
            },
        )
        return decision

    def plan(self, plugin_id: str, context: IntegrationContext) -> IntegrationPlan:
        plugin = self._plugin(plugin_id, context.request_id)
        self._validate_context(plugin, context)
        result = plugin.plan(context)
        if result.plugin_id != plugin.manifest.plugin_id or result.request_id != context.request_id:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.INTERNAL_ERROR,
                    message="integration plugin returned an invalid plan identity",
                    request_id=context.request_id,
                    plugin_id=plugin_id,
                ),
                status_code=500,
            )
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
        plugin = self._plugin(plugin_id, context.request_id)
        self._validate_context(plugin, context)
        if len(observations) > 256:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.INVALID_REQUEST,
                    message="at most 256 observations may be submitted per analysis",
                    request_id=context.request_id,
                    plugin_id=plugin_id,
                    details={"observations": "maximum batch size is 256"},
                ),
                status_code=422,
            )
        try:
            normalized = [NormalizedObservation.model_validate(item) for item in observations]
        except ValidationError as exc:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.INVALID_REQUEST,
                    message="observations do not match the supported integration contract",
                    request_id=context.request_id,
                    plugin_id=plugin_id,
                    details={"observations": "invalid normalized observation"},
                ),
                status_code=422,
            ) from exc
        for observation in normalized:
            if observation.tenant_id != context.tenant_id:
                raise IntegrationKernelError(
                    IntegrationError(
                        code=IntegrationErrorCode.TENANT_MISMATCH,
                        message="observation tenant does not match the authenticated integration tenant",
                        request_id=context.request_id,
                        plugin_id=plugin_id,
                        details={"tenant_id": "observation tenant mismatch"},
                    ),
                    status_code=422,
                )
        result = plugin.analyze(context, [observation.model_dump(mode="json") for observation in normalized])
        if result.plugin_id != plugin.manifest.plugin_id or result.request_id != context.request_id:
            raise IntegrationKernelError(
                IntegrationError(
                    code=IntegrationErrorCode.INTERNAL_ERROR,
                    message="integration plugin returned an invalid analysis identity",
                    request_id=context.request_id,
                    plugin_id=plugin_id,
                ),
                status_code=500,
            )
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
