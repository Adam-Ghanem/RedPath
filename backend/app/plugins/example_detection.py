from __future__ import annotations

from typing import Any

from app.kernel.contracts import IntegrationContext, ModuleKind, NormalizedObservation
from app.plugins.base import DetectionPluginBase, PluginManifest
from app.schemas.contracts import FindingInput

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_MAX_TEXT = 600


def _bounded_text(value: Any, default: str) -> str:
    if not isinstance(value, str) or not value.strip():
        return default
    return value.strip()[:_MAX_TEXT]


def _bounded_evidence(
    observation: NormalizedObservation,
    attrs: dict[str, Any],
    rule_id: str,
    remediation: str,
) -> dict[str, Any]:
    references = attrs.get("evidence_refs", [])
    if not isinstance(references, list):
        references = []
    return {
        "observation_id": observation.observation_id,
        "source": observation.source,
        "kind": observation.kind,
        "rule_id": rule_id,
        "evidence_refs": [str(item)[:128] for item in references[:8]],
        "remediation": remediation,
    }


class SafeObservationDetectionPlugin(DetectionPluginBase):
    """Example deterministic detection plugin for normalized defensive observations."""

    manifest = PluginManifest(
        plugin_id="detection.safe_observation_rules",
        name="Safe observation detection rules",
        version="0.1.0",
        capabilities=("detection", "finding_correlation"),
        mitre_techniques=("T1558.003", "T1558.004", "T1649"),
        required_scopes=("evidence.read",),
        supports_dry_run=True,
        read_only=True,
        module_kind=ModuleKind.DETECTION,
    )

    def detect(
        self,
        context: IntegrationContext,
        observations: list[NormalizedObservation],
    ) -> list[FindingInput]:
        del context
        findings: list[FindingInput] = []
        for observation in observations:
            attrs = observation.attributes
            rule_id = _bounded_text(attrs.get("rule_id"), "")
            technique_id = _bounded_text(attrs.get("technique_id"), "")
            if not rule_id or not technique_id:
                continue
            severity = attrs.get("severity") if attrs.get("severity") in _ALLOWED_SEVERITIES else "medium"
            title = _bounded_text(attrs.get("title"), f"Detection rule {rule_id} matched")
            description = _bounded_text(
                attrs.get("description"),
                f"Rule {rule_id} produced a normalized observation for technique {technique_id}.",
            )
            remediation = _bounded_text(
                attrs.get("remediation"),
                "Review the evidence and apply the approved defensive control for this detection.",
            )
            cvss_score = attrs.get("cvss_score")
            if not isinstance(cvss_score, (int, float)) or not 0 <= cvss_score <= 10:
                cvss_score = None
            findings.append(
                FindingInput(
                    title=title,
                    description=description,
                    severity=severity,
                    asset_id=_bounded_text(attrs.get("asset_id"), "") or None,
                    technique_id=technique_id,
                    cvss_score=cvss_score,
                    evidence=_bounded_evidence(observation, attrs, rule_id, remediation),
                )
            )
        return findings


EXAMPLE_DETECTION_PLUGIN = SafeObservationDetectionPlugin()
