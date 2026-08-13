from dataclasses import dataclass
from typing import Protocol

from app.kernel.contracts import IntegrationAnalysis, IntegrationContext, IntegrationPlan


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


class RedPathPlugin(Protocol):
    manifest: PluginManifest

    def plan(self, context: IntegrationContext) -> IntegrationPlan:
        """Return declarative actions without executing external work."""
        ...

    def analyze(self, context: IntegrationContext, observations: list[dict]) -> IntegrationAnalysis:
        """Analyze normalized observation payloads and return typed findings."""
        ...
