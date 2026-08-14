from __future__ import annotations

import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable

from app.schemas.contracts import (
    CoverageDriftReport,
    CoverageDriftRequest,
    FalsePositiveReview,
    FalsePositiveReviewCreate,
    RegressionTrendReport,
    RegressionTrendRequest,
    RuleDeprecationReport,
    RuleDeprecationWindow,
    TuningProposal,
    TuningProposalCreate,
    TuningProposalReviewRequest,
)
from app.services.detection_framework import DetectionRuleCatalog


class DetectionQualityError(ValueError):
    """A safe, user-actionable quality-operation validation failure."""


class DetectionQualityNotFound(DetectionQualityError):
    """A tenant-scoped quality record was not found."""


class DetectionQualityService:
    """Bounded process-scoped review queue and deterministic fixture-quality calculations."""

    def __init__(
        self,
        catalog: DetectionRuleCatalog,
        *,
        now_fn: Callable[[], datetime] | None = None,
        max_proposals_per_tenant: int = 500,
        max_reviews_per_tenant: int = 2000,
    ) -> None:
        self.catalog = catalog
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.max_proposals_per_tenant = max_proposals_per_tenant
        self.max_reviews_per_tenant = max_reviews_per_tenant
        self._proposals: dict[str, dict[str, TuningProposal]] = defaultdict(dict)
        self._false_positive_reviews: dict[str, list[FalsePositiveReview]] = defaultdict(list)

    def _now(self) -> datetime:
        current = self.now_fn()
        if current.tzinfo is None:
            raise DetectionQualityError("quality operation clock must be timezone-aware")
        return current.astimezone(timezone.utc)

    def _rule_version(self, rule_id: str, requested_version: int) -> None:
        try:
            rule = self.catalog.select([rule_id])[0]
        except (IndexError, KeyError) as exc:
            raise DetectionQualityNotFound(f"unknown or disabled rule: {rule_id}") from exc
        if rule.version != requested_version:
            raise DetectionQualityError(f"rule version mismatch for {rule_id}")

    def create_tuning_proposal(
        self,
        request: TuningProposalCreate,
        *,
        tenant_id: str,
        actor: str,
    ) -> TuningProposal:
        self._rule_version(request.rule_id, request.rule_version)
        proposals = self._proposals[tenant_id]
        if len(proposals) >= self.max_proposals_per_tenant:
            raise DetectionQualityError("tenant tuning-proposal capacity reached")
        now = self._now()
        if request.proposal_type == "deprecate_rule":
            if request.proposed_sunset_at is None or request.proposed_sunset_at <= now:
                raise DetectionQualityError("deprecation proposal requires a future timezone-aware sunset")
            if not request.replacement_rule_id:
                raise DetectionQualityError("deprecation proposal requires a replacement rule ID")
            if request.replacement_rule_id == request.rule_id:
                raise DetectionQualityError("replacement rule must differ from deprecated rule")
        proposal = TuningProposal(
            proposal_id=f"tune-{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            rule_id=request.rule_id,
            rule_version=request.rule_version,
            proposal_type=request.proposal_type,
            summary=request.summary,
            rationale=request.rationale,
            evidence_fixture_ids=sorted(set(request.evidence_fixture_ids)),
            target_false_positive_rate=request.target_false_positive_rate,
            proposed_window_seconds=request.proposed_window_seconds,
            proposed_sunset_at=request.proposed_sunset_at,
            replacement_rule_id=request.replacement_rule_id,
            status="proposed",
            created_by=actor,
            created_at=now,
        )
        proposals[proposal.proposal_id] = proposal
        return proposal

    def list_tuning_proposals(self, *, tenant_id: str) -> list[TuningProposal]:
        return [
            item.model_copy(deep=True)
            for item in sorted(self._proposals[tenant_id].values(), key=lambda value: value.proposal_id)
        ]

    def review_tuning_proposal(
        self,
        proposal_id: str,
        request: TuningProposalReviewRequest,
        *,
        tenant_id: str,
        reviewer: str,
    ) -> TuningProposal:
        proposal = self._proposals[tenant_id].get(proposal_id)
        if proposal is None:
            raise DetectionQualityNotFound("tuning proposal not found")
        if proposal.status != "proposed":
            raise DetectionQualityError("tuning proposal has already been reviewed")
        if reviewer == proposal.created_by:
            raise DetectionQualityError("proposal creator cannot review their own proposal")
        reviewed = proposal.model_copy(
            update={
                "status": "approved" if request.decision == "approve" else "rejected",
                "reviewed_by": reviewer,
                "reviewed_at": self._now(),
                "review_note": request.review_note,
            }
        )
        self._proposals[tenant_id][proposal_id] = reviewed
        return reviewed

    def record_false_positive_review(
        self,
        request: FalsePositiveReviewCreate,
        *,
        tenant_id: str,
        reviewer: str,
    ) -> FalsePositiveReview:
        self._rule_version(request.rule_id, request.rule_version)
        reviews = self._false_positive_reviews[tenant_id]
        if len(reviews) >= self.max_reviews_per_tenant:
            raise DetectionQualityError("tenant false-positive review capacity reached")
        review = FalsePositiveReview(
            review_id=f"fpr-{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            alert_id=request.alert_id,
            rule_id=request.rule_id,
            rule_version=request.rule_version,
            classification=request.classification,
            reason_code=request.reason_code,
            analyst_note=request.analyst_note,
            evidence_fixture_id=request.evidence_fixture_id,
            reviewed_by=reviewer,
            reviewed_at=self._now(),
        )
        reviews.append(review)
        return review

    @staticmethod
    def compare_coverage_drift(request: CoverageDriftRequest, *, tenant_id: str) -> CoverageDriftReport:
        baseline = request.baseline
        current = request.current
        if baseline.tenant_id != tenant_id or current.tenant_id != tenant_id:
            raise DetectionQualityError("quality snapshots must match authenticated tenant")
        coverage_delta = round(current.coverage_percent - baseline.coverage_percent, 2)
        path_delta = round(current.path_coverage_percent - baseline.path_coverage_percent, 2)
        tpr_delta = round(current.true_positive_rate - baseline.true_positive_rate, 2)
        fpr_delta = round(current.false_positive_rate - baseline.false_positive_rate, 2)
        reasons: list[str] = []
        if coverage_delta < -request.thresholds.max_coverage_drop_percent:
            reasons.append("rule coverage decreased beyond threshold")
        if path_delta < -request.thresholds.max_path_coverage_drop_percent:
            reasons.append("path coverage decreased beyond threshold")
        if tpr_delta < -request.thresholds.max_true_positive_drop_percent:
            reasons.append("true-positive rate decreased beyond threshold")
        if fpr_delta > request.thresholds.max_false_positive_increase_percent:
            reasons.append("false-positive rate increased beyond threshold")
        return CoverageDriftReport(
            tenant_id=tenant_id,
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current.snapshot_id,
            coverage_delta_percent=coverage_delta,
            path_coverage_delta_percent=path_delta,
            true_positive_delta_percent=tpr_delta,
            false_positive_delta_percent=fpr_delta,
            drift_detected=bool(reasons),
            drift_reasons=reasons,
            rationale=(
                "Coverage drift compares the current bounded fixture snapshot to the baseline using signed "
                "percentage-point deltas. "
                + (
                    "At least one configured threshold was exceeded."
                    if reasons
                    else "No configured threshold was exceeded."
                )
            ),
        )

    @staticmethod
    def regression_trend(request: RegressionTrendRequest, *, tenant_id: str) -> RegressionTrendReport:
        if request.tenant_id != tenant_id:
            raise DetectionQualityError("regression trend tenant does not match authenticated tenant")
        points = sorted(request.points, key=lambda point: (point.captured_at, point.run_id))
        if len({point.run_id for point in points}) != len(points):
            raise DetectionQualityError("regression trend run IDs must be unique")
        first = points[0]
        last = points[-1]
        tpr_delta = round(last.true_positive_rate - first.true_positive_rate, 2)
        fpr_delta = round(last.false_positive_rate - first.false_positive_rate, 2)
        coverage_delta = round(last.coverage_percent - first.coverage_percent, 2)
        degrading = tpr_delta < 0 or fpr_delta > 0 or coverage_delta < 0
        improving = tpr_delta > 0 or fpr_delta < 0 or coverage_delta > 0
        direction = "degrading" if degrading else "improving" if improving else "stable"
        return RegressionTrendReport(
            tenant_id=tenant_id,
            points=points,
            true_positive_delta_percent=tpr_delta,
            false_positive_delta_percent=fpr_delta,
            coverage_delta_percent=coverage_delta,
            direction=direction,
            rationale=(
                f"Trend contains {len(points)} deterministic fixture-run point(s), ordered by capture time. "
                f"The latest point is {direction} relative to the earliest point."
            ),
        )

    def deprecation_report(self, *, now: datetime | None = None) -> RuleDeprecationReport:
        current = (now or self._now()).astimezone(timezone.utc)
        windows: list[RuleDeprecationWindow] = []
        warnings: list[str] = []
        for rule in self.catalog.list_rules():
            sunset = rule.deprecation_sunset_at
            if rule.deprecation_status == "active" or sunset is None:
                windows.append(
                    RuleDeprecationWindow(
                        rule_id=rule.rule_id,
                        rule_version=rule.version,
                        status=rule.deprecation_status,
                        sunset_at=sunset,
                        days_remaining=None,
                        replacement_rule_id=rule.replacement_rule_id,
                        rationale=rule.deprecation_reason or "Rule remains active without a scheduled sunset.",
                    )
                )
                continue
            days_remaining = math.ceil((sunset.astimezone(timezone.utc) - current).total_seconds() / 86400)
            status = "deprecated" if days_remaining <= 0 else rule.deprecation_status
            if status == "scheduled" and days_remaining <= 7:
                warnings.append(
                    f"rule {rule.rule_id} reaches its deprecation window within {max(days_remaining, 0)} day(s)"
                )
            windows.append(
                RuleDeprecationWindow(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    status=status,
                    sunset_at=sunset,
                    days_remaining=max(days_remaining, 0),
                    replacement_rule_id=rule.replacement_rule_id,
                    rationale=rule.deprecation_reason or "Rule has a governed deprecation window.",
                )
            )
        return RuleDeprecationReport(windows=windows, warnings=warnings)
