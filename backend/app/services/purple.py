from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.contracts import CoverageObservation, DetectionGapReport, WazuhAlert
from app.services.mitre import get_technique


def _alert_text(alert: WazuhAlert) -> str:
    rule_text = " ".join(str(value) for value in alert.rule.values())
    data_text = " ".join(str(value) for value in alert.data.values())
    return f"{rule_text} {data_text}".lower()


def build_detection_gap_report(expected_ids: list[str], alerts: list[WazuhAlert]) -> DetectionGapReport:
    observations: list[CoverageObservation] = []
    for technique_id in expected_ids:
        technique = get_technique(technique_id)
        matching_alerts: list[WazuhAlert] = []
        for alert in alerts:
            text = _alert_text(alert)
            if technique_id.lower() in text or any(hint.lower() in text for hint in technique.evidence_hints):
                matching_alerts.append(alert)
        detected = bool(matching_alerts)
        recommendation = ""
        if not detected:
            recommendation = (
                f"Tune Wazuh rules for {technique_id} ({technique.name}); correlate the relevant Windows/AD "
                f"events and add a regression test using a synthetic lab fixture."
            )
        observations.append(
            CoverageObservation(
                technique_id=technique_id,
                detected=detected,
                evidence_count=len(matching_alerts),
                alert_ids=[alert.id for alert in matching_alerts if alert.id],
                recommendation=recommendation,
            )
        )
    coverage = (sum(1 for item in observations if item.detected) / len(observations)) * 100
    return DetectionGapReport(
        run_id=str(uuid.uuid4()),
        coverage_percent=round(coverage, 2),
        observations=observations,
        gaps=[item.technique_id for item in observations if not item.detected],
        generated_at=datetime.now(timezone.utc),
    )
