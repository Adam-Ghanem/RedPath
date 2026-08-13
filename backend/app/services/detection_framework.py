from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.models.telemetry import TelemetryEvent
from app.schemas.contracts import (
    AttackPathEvidence,
    DetectionCondition,
    DetectionCoverageObservation,
    DetectionCoverageReport,
    DetectionEvaluationResponse,
    DetectionMatch,
    DetectionRule,
    DetectionRuleProvenance,
    NormalizedRegressionCaseResult,
    NormalizedRegressionFixture,
    NormalizedRegressionReport,
    RegressionCaseResult,
    RegressionFixture,
    RegressionReport,
    WazuhAlert,
)

_BUILTIN_RULES = [
    DetectionRule(
        rule_id="ad.kerberoasting.service-ticket",
        title="Kerberoasting service-ticket signal",
        description="Correlate unusual service-ticket requests with a Kerberoasting detection signal.",
        technique_ids=["T1558.003"],
        severity="high",
        event_sources=["wazuh"],
        conditions=[
            DetectionCondition(path="data.event_id", operator="equals", value="4769"),
            DetectionCondition(path="rule.description", operator="contains", value="T1558.003"),
        ],
        window_seconds=300,
        group_by=["data.srcuser"],
        deployment_status="testing",
        owner="redpath-detection",
        telemetry_requirements=["wazuh.security"],
        tags=["identity", "kerberos"],
    ),
    DetectionRule(
        rule_id="ad.asrep.preauth-disabled",
        title="AS-REP roasting pre-authentication exception",
        description="Detect an AS-REP roasting signal paired with a disabled pre-authentication state.",
        technique_ids=["T1558.004"],
        severity="high",
        event_sources=["wazuh"],
        conditions=[
            DetectionCondition(path="data.preauth_required", operator="equals", value=False),
            DetectionCondition(path="rule.description", operator="contains", value="T1558.004"),
        ],
        window_seconds=300,
        group_by=["data.srcuser"],
        deployment_status="testing",
        owner="redpath-detection",
        telemetry_requirements=["wazuh.security"],
        tags=["identity", "kerberos"],
    ),
    DetectionRule(
        rule_id="adcs.template.client-auth",
        title="AD CS client-authentication template risk",
        description="Correlate an AD CS template signal with enrollee-controlled subject and client authentication.",
        technique_ids=["T1649"],
        severity="critical",
        event_sources=["wazuh"],
        conditions=[
            DetectionCondition(path="data.enrollee_supplies_subject", operator="equals", value=True),
            DetectionCondition(path="data.client_auth_eku", operator="equals", value=True),
            DetectionCondition(path="rule.description", operator="contains", value="T1649"),
        ],
        window_seconds=300,
        group_by=["data.host"],
        deployment_status="testing",
        owner="redpath-detection",
        telemetry_requirements=["wazuh.security"],
        tags=["identity", "adcs"],
    ),
]


def _event_source(alert: WazuhAlert) -> str:
    source = alert.data.get("source") or alert.rule.get("source") or "wazuh"
    return str(source).lower()


def _get_path(alert: WazuhAlert, path: str) -> Any:
    current: Any = alert.model_dump()
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _value_matches(actual: Any, condition: DetectionCondition) -> bool:
    if actual is None:
        return False
    expected = condition.value
    if condition.operator == "equals":
        if isinstance(actual, bool) or isinstance(expected, bool):
            return actual is expected
        return str(actual).casefold() == str(expected).casefold()
    if condition.operator == "contains":
        if isinstance(actual, list):
            return any(str(expected).casefold() in str(item).casefold() for item in actual)
        return str(expected).casefold() in str(actual).casefold()
    if condition.operator == "starts_with":
        return str(actual).casefold().startswith(str(expected).casefold())
    if condition.operator == "in":
        if not isinstance(expected, list):
            return False
        return any(str(actual).casefold() == str(item).casefold() for item in expected)
    return False


def _parse_timestamp(alert: WazuhAlert) -> datetime | None:
    if not alert.timestamp:
        return None
    try:
        return datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def _group_key(alert: WazuhAlert, rule: DetectionRule) -> str:
    if not rule.group_by:
        return "all-events"
    values = [str(_get_path(alert, path) or "<missing>") for path in rule.group_by]
    return "|".join(values)


def _within_window(alerts: list[WazuhAlert], rule: DetectionRule) -> bool:
    timestamps = [_parse_timestamp(alert) for alert in alerts]
    if any(timestamp is None for timestamp in timestamps):
        return True
    ordered = sorted(timestamp for timestamp in timestamps if timestamp is not None)
    return (ordered[-1] - ordered[0]).total_seconds() <= rule.window_seconds


def _match_rule(
    rule: DetectionRule,
    events: list[WazuhAlert],
    *,
    provenance_sha256: str | None = None,
    path_evidence_ids: list[str] | None = None,
) -> list[DetectionMatch]:
    allowed_sources = {source.lower() for source in rule.event_sources}
    source_events = [event for event in events if _event_source(event) in allowed_sources]
    grouped: dict[str, list[WazuhAlert]] = defaultdict(list)
    for event in source_events:
        grouped[_group_key(event, rule)].append(event)

    matches: list[DetectionMatch] = []
    for group_key, group_events in grouped.items():
        condition_events = [
            [event for event in group_events if _value_matches(_get_path(event, condition.path), condition)]
            for condition in rule.conditions
        ]
        matched_conditions = sum(bool(items) for items in condition_events)
        condition_satisfied = (
            matched_conditions == len(rule.conditions)
            if rule.match_mode == "all"
            else matched_conditions > 0
        )
        if not condition_satisfied:
            continue
        evidence = {event.id for items in condition_events for event in items if event.id}
        correlated_events = [event for event in group_events if event.id in evidence] if evidence else group_events
        if not _within_window(correlated_events, rule):
            continue
        timestamps = [_parse_timestamp(event) for event in correlated_events]
        valid_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
        matches.append(
            DetectionMatch(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                technique_ids=rule.technique_ids,
                alert_ids=sorted(evidence),
                matched_condition_count=matched_conditions,
                first_seen=min(valid_timestamps) if valid_timestamps else None,
                last_seen=max(valid_timestamps) if valid_timestamps else None,
                group_key=group_key,
                rationale=(
                    f"Matched {matched_conditions}/{len(rule.conditions)} conditions from "
                    f"{len(evidence)} correlated event(s) within {rule.window_seconds}s."
                ),
                provenance_sha256=provenance_sha256,
                path_evidence_ids=sorted(set(path_evidence_ids or [])),
            )
        )
    return matches


def _builtin_fixtures() -> list[RegressionFixture]:
    return [
        RegressionFixture(
            fixture_id="ad.kerberoasting.positive",
            title="Synthetic Kerberoasting alert is detected",
            rule_id="ad.kerberoasting.service-ticket",
            expected_match=True,
            events=[
                WazuhAlert(
                    id="fixture-kerberoast-positive",
                    timestamp="2026-08-12T02:00:00Z",
                    rule={"description": "T1558.003 Kerberoasting signal: unusual service ticket request"},
                    data={"event_id": "4769", "srcuser": "analyst01", "dstuser": "svc_sql"},
                )
            ],
        ),
        RegressionFixture(
            fixture_id="ad.kerberoasting.negative",
            title="Benign service ticket does not alert",
            rule_id="ad.kerberoasting.service-ticket",
            expected_match=False,
            events=[
                WazuhAlert(
                    id="fixture-kerberoast-negative",
                    timestamp="2026-08-12T02:00:00Z",
                    rule={"description": "Normal service ticket request"},
                    data={"event_id": "4769", "srcuser": "service-account", "dstuser": "svc_sql"},
                )
            ],
        ),
        RegressionFixture(
            fixture_id="ad.asrep.positive",
            title="Synthetic AS-REP exception is detected",
            rule_id="ad.asrep.preauth-disabled",
            expected_match=True,
            events=[
                WazuhAlert(
                    id="fixture-asrep-positive",
                    timestamp="2026-08-12T02:01:00Z",
                    rule={"description": "T1558.004 AS-REP roasting signal"},
                    data={"preauth_required": False, "srcuser": "analyst01"},
                )
            ],
        ),
        RegressionFixture(
            fixture_id="adcs.template.positive",
            title="Synthetic AD CS template risk is detected",
            rule_id="adcs.template.client-auth",
            expected_match=True,
            events=[
                WazuhAlert(
                    id="fixture-adcs-positive",
                    timestamp="2026-08-12T02:02:00Z",
                    rule={"description": "T1649 AD CS template risk"},
                    data={"enrollee_supplies_subject": True, "client_auth_eku": True, "host": "CA-01"},
                )
            ],
        ),
    ]


def _rule_content_sha256(rule: DetectionRule) -> str:
    canonical = json.dumps(rule.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _telemetry_event_to_alert(event: TelemetryEvent) -> WazuhAlert:
    data: dict[str, Any] = dict(event.safe_fields)
    data.update(event.correlation_fields)
    data["source"] = event.source
    data["technique_ids"] = list(event.technique_ids)
    if event.rule_id:
        data["rule_id"] = event.rule_id
    return WazuhAlert(
        id=event.event_id,
        timestamp=event.observed_at.astimezone(timezone.utc).isoformat(),
        rule={"description": event.rule_description or "", "id": event.rule_id or "", "source": event.source},
        data=data,
    )


class DetectionRuleCatalog:
    """Process-scoped rule catalog with deterministic, non-executable rule semantics."""

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {rule.rule_id: rule for rule in _BUILTIN_RULES}
        self._sources: dict[str, str] = {rule.rule_id: "builtin" for rule in _BUILTIN_RULES}

    def list_rules(self) -> list[DetectionRule]:
        return [self._rules[rule_id].model_copy(deep=True) for rule_id in sorted(self._rules)]

    def add_rule(self, rule: DetectionRule) -> DetectionRule:
        if rule.deployment_status == "production" and not rule.requires_approval:
            raise ValueError("production rules must require approval")
        if rule.deployment_status == "production" and (
            rule.approval_state != "approved" or not rule.reviewed_by or rule.reviewed_at is None
        ):
            raise ValueError("production rules require approved state, reviewer, review timestamp, and approval flag")
        if rule.rule_id in self._rules:
            raise ValueError(f"rule_id already exists: {rule.rule_id}")
        self._rules[rule.rule_id] = rule.model_copy(deep=True)
        self._sources[rule.rule_id] = "registered"
        return rule

    def provenance(self, rule_ids: list[str] | None = None) -> list[DetectionRuleProvenance]:
        selected = self.list_rules() if not rule_ids else [self._rules[rule_id] for rule_id in sorted(set(rule_ids))]
        return [
            DetectionRuleProvenance(
                rule_id=rule.rule_id,
                version=rule.version,
                source=self._sources[rule.rule_id],
                content_sha256=_rule_content_sha256(rule),
                deployment_status=rule.deployment_status,
                requires_approval=rule.requires_approval,
            )
            for rule in selected
        ]

    def select(self, rule_ids: list[str]) -> list[DetectionRule]:
        selected = (
            self.list_rules()
            if not rule_ids
            else [self._rules[rule_id].model_copy(deep=True) for rule_id in sorted(set(rule_ids))]
        )
        return [rule for rule in selected if rule.enabled]

    def evaluate(
        self,
        events: list[WazuhAlert],
        rule_ids: list[str],
        *,
        tenant_id: str | None = None,
        actor: str | None = None,
        path_evidence_ids_by_rule: dict[str, list[str]] | None = None,
    ) -> DetectionEvaluationResponse:
        rules = self.select(rule_ids)
        provenance = self.provenance([rule.rule_id for rule in rules])
        digest_by_rule = {item.rule_id: item.content_sha256 for item in provenance}
        matches = [
            match
            for rule in rules
            for match in _match_rule(
                rule,
                events,
                provenance_sha256=digest_by_rule[rule.rule_id],
                path_evidence_ids=(path_evidence_ids_by_rule or {}).get(rule.rule_id),
            )
        ]
        return DetectionEvaluationResponse(
            evaluated_at=datetime.now(timezone.utc),
            event_count=len(events),
            rule_count=len(rules),
            matches=matches,
            tenant_id=tenant_id,
            actor=actor,
            rule_provenance=provenance,
        )

    def evaluate_normalized_telemetry(
        self,
        events: list[TelemetryEvent],
        rule_ids: list[str],
        *,
        tenant_id: str,
        actor: str,
        attack_paths: list[AttackPathEvidence] | None = None,
    ) -> DetectionEvaluationResponse:
        if any(event.tenant_id != tenant_id for event in events):
            raise ValueError("telemetry tenant does not match authenticated tenant")
        paths = attack_paths or []
        if any(path.tenant_id != tenant_id for path in paths):
            raise ValueError("attack-path evidence tenant does not match authenticated tenant")
        path_ids_by_rule: dict[str, list[str]] = defaultdict(list)
        event_assets = {event.asset_id for event in events if event.asset_id}
        path_context = [(path.path_id, set(path.technique_ids), set(path.asset_ids)) for path in paths]
        selected_rules = self.select(rule_ids)
        for rule in selected_rules:
            for path_id, technique_ids, path_assets in path_context:
                technique_match = technique_ids.intersection(rule.technique_ids)
                asset_match = not path_assets or bool(event_assets.intersection(path_assets))
                if technique_match and asset_match:
                    path_ids_by_rule[rule.rule_id].append(path_id)
        alerts = [_telemetry_event_to_alert(event) for event in events]
        return self.evaluate(
            alerts,
            rule_ids,
            tenant_id=tenant_id,
            actor=actor,
            path_evidence_ids_by_rule=path_ids_by_rule,
        )

    def coverage_report(
        self,
        events: list[TelemetryEvent],
        rule_ids: list[str],
        *,
        tenant_id: str,
        actor: str,
        attack_paths: list[AttackPathEvidence] | None = None,
        dry_run: bool = True,
    ) -> DetectionCoverageReport:
        paths = attack_paths or []
        evaluation = self.evaluate_normalized_telemetry(
            events,
            rule_ids,
            tenant_id=tenant_id,
            actor=actor,
            attack_paths=paths,
        )
        selected_rules = self.select(rule_ids)
        matches_by_rule: dict[str, list[DetectionMatch]] = defaultdict(list)
        for match in evaluation.matches:
            matches_by_rule[match.rule_id].append(match)
        observations: list[DetectionCoverageObservation] = []
        for rule in selected_rules:
            matches = matches_by_rule.get(rule.rule_id, [])
            event_ids = sorted({event_id for match in matches for event_id in match.alert_ids})
            path_ids = sorted({path_id for match in matches for path_id in match.path_evidence_ids})
            detected = bool(matches)
            rationale = (
                f"{rule.title} v{rule.version} ({rule.severity}) uses {len(rule.conditions)} declared "
                f"condition(s) within {rule.window_seconds}s. "
                f"Evidence provenance is {self.provenance([rule.rule_id])[0].content_sha256}."
            )
            if detected:
                rationale += f" Matched {len(event_ids)} normalized telemetry event(s)."
            recommendation = "" if detected else "Add or tune a reviewed normalized-telemetry regression fixture."
            observations.append(
                DetectionCoverageObservation(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    technique_ids=rule.technique_ids,
                    detected=detected,
                    evidence_count=len(event_ids),
                    telemetry_event_ids=event_ids,
                    path_evidence_ids=path_ids,
                    rationale=rationale,
                    recommendation=recommendation,
                )
            )
        detected_count = sum(1 for item in observations if item.detected)
        covered_paths = sorted({path_id for item in observations for path_id in item.path_evidence_ids})
        path_ids = sorted(path.path_id for path in paths)
        coverage_percent = round((detected_count / len(selected_rules)) * 100, 2) if selected_rules else 0.0
        path_coverage_percent = round((len(covered_paths) / len(path_ids)) * 100, 2) if path_ids else 0.0
        return DetectionCoverageReport(
            run_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            actor=actor,
            evaluated_at=evaluation.evaluated_at,
            expected_rule_count=len(selected_rules),
            detected_rule_count=detected_count,
            coverage_percent=coverage_percent,
            path_count=len(path_ids),
            covered_path_count=len(covered_paths),
            path_coverage_percent=path_coverage_percent,
            observations=observations,
            path_evidence_ids=covered_paths,
            rule_provenance=evaluation.rule_provenance,
            dry_run=dry_run,
            warnings=[],
        )

    def run_normalized_regressions(
        self,
        fixtures: list[NormalizedRegressionFixture],
        rule_ids: list[str],
        *,
        tenant_id: str,
        actor: str,
        dry_run: bool = True,
    ) -> NormalizedRegressionReport:
        selected_ids = set(rule_ids)
        cases = sorted(
            [fixture for fixture in fixtures if not selected_ids or fixture.rule_id in selected_ids],
            key=lambda fixture: fixture.fixture_id,
        )
        results: list[NormalizedRegressionCaseResult] = []
        for case in cases:
            if any(event.tenant_id != tenant_id for event in case.telemetry):
                raise ValueError("regression telemetry tenant does not match authenticated tenant")
            if any(path.tenant_id != tenant_id for path in case.attack_paths):
                raise ValueError("regression attack-path tenant does not match authenticated tenant")
            evaluation = self.evaluate_normalized_telemetry(
                case.telemetry,
                [case.rule_id],
                tenant_id=tenant_id,
                actor=actor,
                attack_paths=case.attack_paths,
            )
            matches = [match for match in evaluation.matches if match.rule_id == case.rule_id]
            actual_match = bool(matches)
            event_ids = sorted({event_id for match in matches for event_id in match.alert_ids})
            path_ids = sorted({path_id for match in matches for path_id in match.path_evidence_ids})
            passed = actual_match == case.expected_match
            results.append(
                NormalizedRegressionCaseResult(
                    fixture_id=case.fixture_id,
                    rule_id=case.rule_id,
                    expected_match=case.expected_match,
                    actual_match=actual_match,
                    passed=passed,
                    telemetry_event_ids=event_ids,
                    path_evidence_ids=path_ids,
                    notes="Expected outcome observed." if passed else "Expected and actual outcomes differ.",
                )
            )
        positive = [result for result in results if result.expected_match]
        negative = [result for result in results if not result.expected_match]
        true_positive_rate = sum(result.actual_match for result in positive) / len(positive) * 100 if positive else 0.0
        false_positive_rate = sum(result.actual_match for result in negative) / len(negative) * 100 if negative else 0.0
        failed_cases = sum(not result.passed for result in results)
        provenance = self.provenance(sorted({case.rule_id for case in cases}))
        return NormalizedRegressionReport(
            run_id=str(uuid.uuid4()),
            status="failed" if failed_cases else "passed",
            tenant_id=tenant_id,
            actor=actor,
            total_cases=len(results),
            passed_cases=len(results) - failed_cases,
            failed_cases=failed_cases,
            true_positive_rate=round(true_positive_rate, 2),
            false_positive_rate=round(false_positive_rate, 2),
            cases=results,
            rule_provenance=provenance,
            generated_at=datetime.now(timezone.utc),
            dry_run=dry_run,
            warnings=[] if cases else ["no regression fixtures matched the requested rule IDs"],
        )

    def run_regressions(
        self,
        fixtures: list[RegressionFixture] | None,
        rule_ids: list[str],
        *,
        tenant_id: str | None = None,
        actor: str | None = None,
    ) -> RegressionReport:
        cases = fixtures if fixtures is not None else _builtin_fixtures()
        selected_ids = set(rule_ids)
        if selected_ids:
            cases = [case for case in cases if case.rule_id in selected_ids]
        results: list[RegressionCaseResult] = []
        for case in cases:
            rule = self._rules.get(case.rule_id)
            if rule is None:
                raise KeyError(f"unknown rule_id: {case.rule_id}")
            actual_matches = _match_rule(rule, case.events)
            actual_match = bool(actual_matches)
            passed = actual_match == case.expected_match
            alert_ids = sorted({alert_id for match in actual_matches for alert_id in match.alert_ids})
            results.append(
                RegressionCaseResult(
                    fixture_id=case.fixture_id,
                    rule_id=case.rule_id,
                    expected_match=case.expected_match,
                    actual_match=actual_match,
                    passed=passed,
                    alert_ids=alert_ids,
                    notes="Expected outcome observed." if passed else "Expected and actual outcomes differ.",
                )
            )
        positive = [result for result in results if result.expected_match]
        negative = [result for result in results if not result.expected_match]
        true_positive_rate = (
            sum(result.actual_match for result in positive) / len(positive) * 100 if positive else 0.0
        )
        false_positive_rate = (
            sum(result.actual_match for result in negative) / len(negative) * 100 if negative else 0.0
        )
        failed_cases = sum(not result.passed for result in results)
        return RegressionReport(
            run_id=str(uuid.uuid4()),
            status="failed" if failed_cases else "passed",
            total_cases=len(results),
            passed_cases=len(results) - failed_cases,
            failed_cases=failed_cases,
            true_positive_rate=round(true_positive_rate, 2),
            false_positive_rate=round(false_positive_rate, 2),
            cases=results,
            generated_at=datetime.now(timezone.utc),
            tenant_id=tenant_id,
            actor=actor,
            rule_provenance=self.provenance(sorted({case.rule_id for case in cases})),
        )


def builtin_regression_fixtures() -> list[RegressionFixture]:
    return [fixture.model_copy(deep=True) for fixture in _builtin_fixtures()]
