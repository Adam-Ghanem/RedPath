from __future__ import annotations

from dataclasses import dataclass

import pytest
from app.kernel.contracts import (
    CapabilityNegotiationRequest,
    IntegrationContext,
    ModuleKind,
)
from app.plugins.base import DetectionPluginBase, PluginManifest
from app.plugins.example_detection import EXAMPLE_DETECTION_PLUGIN
from app.plugins.registry import DEFAULT_REGISTRY, PluginRegistry


@dataclass
class FakeEntryPoint:
    name: str
    loaded: object
    load_count: int = 0

    def load(self):
        self.load_count += 1
        return self.loaded


class FixtureDetectionPlugin(DetectionPluginBase):
    manifest = PluginManifest(
        plugin_id="test.detection_plugin",
        name="Test detection plugin",
        version="1.0.0",
        capabilities=("detection",),
        module_kind=ModuleKind.DETECTION,
        required_scopes=("evidence.read",),
    )

    def detect(self, context, observations):
        del context
        return [
            {
                "title": observation.attributes["title"],
                "description": "fixture finding",
                "severity": "low",
                "technique_id": "T1558.003",
                "evidence": {"observation_id": observation.observation_id},
            }
            for observation in observations
            if observation.attributes.get("title")
        ]


def _context() -> IntegrationContext:
    return IntegrationContext(
        tenant_id="tenant-a",
        actor="analyst-a",
        request_id="plugin-test-1",
        requested_capabilities=("detection",),
        dry_run=True,
    )


def test_example_detection_plugin_emits_valid_bounded_findings() -> None:
    result = EXAMPLE_DETECTION_PLUGIN.analyze(
        _context(),
        [
            {
                "observation_id": "obs-1",
                "tenant_id": "tenant-a",
                "source": "wazuh",
                "kind": "alert_summary",
                "attributes": {
                    "rule_id": "rule-kerberoast",
                    "technique_id": "T1558.003",
                    "severity": "high",
                    "title": "Service ticket exposure",
                    "asset_id": "asset-1",
                    "evidence_refs": ["evidence-1"],
                    "remediation": "Rotate the service credential.",
                    "raw_event": "must never be copied",
                },
            }
        ],
    )

    assert result.observation_count == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "high"
    assert finding.technique_id == "T1558.003"
    assert finding.evidence["remediation"] == "Rotate the service credential."
    assert "raw_event" not in finding.evidence


def test_example_detection_plugin_skips_observations_without_rule_and_technique() -> None:
    result = EXAMPLE_DETECTION_PLUGIN.analyze(
        _context(),
        [
            {
                "observation_id": "obs-incomplete",
                "tenant_id": "tenant-a",
                "source": "wazuh",
                "kind": "alert_summary",
                "attributes": {"title": "Not enough context"},
            }
        ],
    )

    assert result.observation_count == 1
    assert result.findings == []


def test_detection_plugin_plan_is_declarative_and_read_only() -> None:
    plan = EXAMPLE_DETECTION_PLUGIN.plan(_context())

    assert plan.dry_run is True
    assert len(plan.actions) == 1
    assert plan.actions[0].operation == "analyze"
    assert plan.actions[0].read_only is True
    assert plan.actions[0].dry_run is True


def test_default_registry_contains_concrete_detection_plugin() -> None:
    registry = DEFAULT_REGISTRY
    decision = registry.negotiate(
        EXAMPLE_DETECTION_PLUGIN.manifest.plugin_id,
        CapabilityNegotiationRequest(
            contract_version="1.0",
            requested_capabilities=("detection",),
            dry_run=True,
        ),
    )

    assert decision.compatible is True
    assert decision.capabilities[0].module_kind == ModuleKind.DETECTION


def test_discovery_loads_only_allow_listed_entry_points() -> None:
    allowed = FakeEntryPoint("test.detection_plugin", FixtureDetectionPlugin)
    skipped = FakeEntryPoint("untrusted.unlisted", FixtureDetectionPlugin)
    registry = PluginRegistry()

    discovered = registry.discover(
        allowed_plugin_ids={"test.detection_plugin"},
        group="redpath.detection",
        entry_points=[skipped, allowed],
    )

    assert discovered == ("test.detection_plugin",)
    assert allowed.load_count == 1
    assert skipped.load_count == 0
    assert registry.get("test.detection_plugin").manifest.module_kind == ModuleKind.DETECTION


def test_discovery_reuses_registry_safety_validation() -> None:
    class UnsafePlugin(FixtureDetectionPlugin):
        manifest = FixtureDetectionPlugin.manifest.__class__(
            plugin_id="test.unsafe_plugin",
            name="Unsafe plugin",
            version="1.0.0",
            capabilities=("detection",),
            module_kind=ModuleKind.DETECTION,
            read_only=False,
            supports_dry_run=False,
        )

    entry_point = FakeEntryPoint("test.unsafe_plugin", UnsafePlugin)
    with pytest.raises(ValueError, match="read-only"):
        PluginRegistry().discover(
            allowed_plugin_ids={"test.unsafe_plugin"},
            entry_points=[entry_point],
        )
    assert entry_point.load_count == 1


def test_discovery_rejects_entry_point_manifest_identity_mismatch() -> None:
    entry_point = FakeEntryPoint("test.approved_name", FixtureDetectionPlugin)

    with pytest.raises(ValueError, match="manifest ID"):
        PluginRegistry().discover(
            allowed_plugin_ids={"test.approved_name"},
            entry_points=[entry_point],
        )
