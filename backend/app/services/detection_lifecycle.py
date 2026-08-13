from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Iterable

from app.schemas.contracts import (
    DetectionCoverageReport,
    DetectionLifecycleGateResponse,
    DetectionPackManifest,
    DetectionRule,
    DetectionRuleValidationResult,
    NormalizedRegressionFixture,
    NormalizedRegressionReport,
)
from app.services.detection_framework import DetectionRuleCatalog
from app.services.mitre import get_technique

_UNSAFE_LOGIC_TERMS = re.compile(
    r"(?:password|credential|secret|token|cookie|private[_ -]?key|shell|"
    r"exploit|inject|malware|persistence|evasion|destructive)",
    re.IGNORECASE,
)


class DetectionLifecycleService:
    """Validate and gate declarative defensive detection packages without external side effects."""

    def __init__(self, catalog: DetectionRuleCatalog) -> None:
        self.catalog = catalog

    @staticmethod
    def _pack_sha256(pack: DetectionPackManifest) -> str:
        canonical = json.dumps(pack.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_logic(rule: DetectionRule) -> tuple[bool, list[str]]:
        errors: list[str] = []
        scalar_types = (str, int, float, bool)
        for condition in rule.conditions:
            candidate = f"{condition.path} {condition.value}"
            if _UNSAFE_LOGIC_TERMS.search(candidate):
                errors.append(f"unsafe detection field or value in condition path {condition.path}")
            value = condition.value
            if condition.operator == "in" and not isinstance(value, list):
                errors.append(f"in operator requires a bounded scalar list for {condition.path}")
            if isinstance(value, dict) or (
                isinstance(value, list) and any(not isinstance(item, scalar_types) for item in value)
            ):
                errors.append(f"condition value must be scalar or scalar list for {condition.path}")
            if not isinstance(value, (list, *scalar_types)):
                errors.append(f"condition value type is not allowed for {condition.path}")
        return not errors, errors

    def validate_rule(self, rule: DetectionRule) -> DetectionRuleValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        mitre_valid = True
        for technique_id in rule.technique_ids:
            try:
                get_technique(technique_id)
            except KeyError:
                mitre_valid = False
                errors.append(f"unsupported MITRE technique: {technique_id}")
        safe_logic, safe_errors = self._safe_logic(rule)
        errors.extend(safe_errors)
        approval_valid = True
        if rule.deployment_status == "production":
            approval_valid = (
                rule.requires_approval
                and rule.approval_state == "approved"
                and bool(rule.reviewed_by)
                and rule.reviewed_at is not None
            )
            if not approval_valid:
                errors.append("production rules require approved state, reviewer, review timestamp, and approval flag")
        elif rule.approval_state == "rejected":
            warnings.append("rule is explicitly rejected and cannot be promoted without a new version")
        if not rule.owner:
            warnings.append("rule owner is empty; assign an owner before production promotion")
        if not rule.telemetry_requirements:
            warnings.append("telemetry requirements are empty; document required normalized sources")
        return DetectionRuleValidationResult(
            rule_id=rule.rule_id,
            version=rule.version,
            valid=not errors,
            mitre_valid=mitre_valid,
            safe_logic=safe_logic,
            approval_valid=approval_valid,
            errors=errors,
            warnings=warnings,
        )

    def validate_pack(
        self, pack: DetectionPackManifest
    ) -> tuple[list[DetectionRuleValidationResult], list[str], list[str]]:
        results: list[DetectionRuleValidationResult] = []
        errors: list[str] = []
        warnings: list[str] = []
        pack_rule_ids = [item.rule_id for item in pack.rules]
        if len(pack_rule_ids) != len(set(pack_rule_ids)):
            errors.append("pack contains duplicate rule IDs")
        fixture_ids: list[str] = []
        for item in pack.rules:
            try:
                rule = self.catalog.select([item.rule_id])[0]
            except (IndexError, KeyError):
                errors.append(f"pack references unknown or disabled rule: {item.rule_id}")
                continue
            if rule.version != item.version:
                errors.append(f"pack rule version mismatch for {item.rule_id}")
            results.append(self.validate_rule(rule))
            fixture_ids.extend(item.fixture_ids)
        if len(fixture_ids) != len(set(fixture_ids)):
            errors.append("pack contains duplicate fixture IDs")
        if not pack.owner.strip():
            errors.append("pack owner is required")
        return results, errors, warnings

    @staticmethod
    def _fixtures_for_pack(
        pack: DetectionPackManifest,
        fixtures: list[NormalizedRegressionFixture],
    ) -> list[NormalizedRegressionFixture]:
        fixture_map = {fixture.fixture_id: fixture for fixture in fixtures}
        selected: list[NormalizedRegressionFixture] = []
        for pack_rule in pack.rules:
            for fixture_id in pack_rule.fixture_ids:
                fixture = fixture_map.get(fixture_id)
                if fixture is None:
                    raise ValueError(f"pack references missing fixture: {fixture_id}")
                if fixture.rule_id != pack_rule.rule_id:
                    raise ValueError(f"fixture {fixture_id} is assigned to the wrong rule")
                selected.append(fixture)
        return sorted(selected, key=lambda fixture: fixture.fixture_id)

    @staticmethod
    def _dedupe_events(fixtures: Iterable[NormalizedRegressionFixture]):
        by_id = {}
        for fixture in fixtures:
            for event in fixture.telemetry:
                by_id[event.event_id] = event
        return [by_id[event_id] for event_id in sorted(by_id)]

    @staticmethod
    def _dedupe_paths(fixtures: Iterable[NormalizedRegressionFixture]):
        by_id = {}
        for fixture in fixtures:
            for path in fixture.attack_paths:
                by_id[path.path_id] = path
        return [by_id[path_id] for path_id in sorted(by_id)]

    def run_gate(
        self,
        pack: DetectionPackManifest,
        fixtures: list[NormalizedRegressionFixture],
        *,
        tenant_id: str,
        actor: str,
        rule_ids: list[str] | None = None,
        dry_run: bool = True,
    ) -> DetectionLifecycleGateResponse:
        validations, pack_errors, pack_warnings = self.validate_pack(pack)
        validation_errors = [error for result in validations for error in result.errors]
        errors = pack_errors + validation_errors
        warnings = pack_warnings + [warning for result in validations for warning in result.warnings]
        pack_rule_ids = {item.rule_id for item in pack.rules}
        selected_rule_ids = rule_ids or sorted(pack_rule_ids)
        unexpected_rule_ids = sorted(set(selected_rule_ids) - pack_rule_ids)
        if unexpected_rule_ids:
            errors.append("requested rule IDs must be declared in the pack: " + ", ".join(unexpected_rule_ids))
        report: NormalizedRegressionReport | None = None
        coverage: DetectionCoverageReport | None = None
        blocked = bool(pack_errors or validation_errors)
        if not errors:
            try:
                selected_fixtures = self._fixtures_for_pack(pack, fixtures)
                if any(event.tenant_id != tenant_id for fixture in selected_fixtures for event in fixture.telemetry):
                    raise ValueError("fixture telemetry tenant does not match authenticated tenant")
                if any(path.tenant_id != tenant_id for fixture in selected_fixtures for path in fixture.attack_paths):
                    raise ValueError("fixture path evidence tenant does not match authenticated tenant")
                report = self.catalog.run_normalized_regressions(
                    selected_fixtures,
                    selected_rule_ids,
                    tenant_id=tenant_id,
                    actor=actor,
                    dry_run=dry_run,
                )
                coverage = self.catalog.coverage_report(
                    self._dedupe_events(selected_fixtures),
                    selected_rule_ids,
                    tenant_id=tenant_id,
                    actor=actor,
                    attack_paths=self._dedupe_paths(selected_fixtures),
                    dry_run=dry_run,
                )
            except (KeyError, ValueError) as exc:
                errors.append(str(exc))
                blocked = True
        baseline = pack.baseline
        observed_tpr = report.true_positive_rate if report else 0.0
        observed_fpr = report.false_positive_rate if report else 0.0
        observed_coverage = coverage.coverage_percent if coverage else 0.0
        observed_path_coverage = coverage.path_coverage_percent if coverage else 0.0
        baseline_errors = []
        if observed_tpr < baseline.min_true_positive_rate:
            baseline_errors.append("true-positive rate is below the pack baseline")
        if observed_fpr > baseline.max_false_positive_rate:
            baseline_errors.append("false-positive rate exceeds the pack baseline")
        if observed_coverage < baseline.min_rule_coverage_percent:
            baseline_errors.append("rule coverage is below the pack baseline")
        if observed_path_coverage < baseline.min_path_coverage_percent:
            baseline_errors.append("path coverage is below the pack baseline")
        errors.extend(baseline_errors)
        status = "passed" if not errors else ("blocked" if blocked else "failed")
        return DetectionLifecycleGateResponse(
            gate_id=str(uuid.uuid4()),
            pack_id=pack.pack_id,
            pack_version=pack.pack_version,
            pack_sha256=self._pack_sha256(pack),
            tenant_id=tenant_id,
            actor=actor,
            status=status,
            validation=validations,
            regression_report=report,
            coverage_report=coverage,
            baseline=baseline,
            observed_true_positive_rate=round(observed_tpr, 2),
            observed_false_positive_rate=round(observed_fpr, 2),
            observed_rule_coverage_percent=round(observed_coverage, 2),
            observed_path_coverage_percent=round(observed_path_coverage, 2),
            errors=errors,
            warnings=warnings,
            dry_run=dry_run,
        )
