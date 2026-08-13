from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.core.audit import AuditLogger
from app.core.auth import Principal, require_roles
from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeViolation
from app.db.models import create_session_factory
from app.plugins.registry import list_plugins
from app.schemas.contracts import (
    AssessmentRunSummary,
    CampaignCreate,
    CampaignExport,
    CampaignLifecycleUpdate,
    CampaignResponse,
    CampaignTimelineEvent,
    CorrelatedRisk,
    CorrelationRequest,
    CoverageScorecard,
    DetectionGapReport,
    DetectionTuningItem,
    EvidenceCreate,
    EvidenceManifest,
    EvidenceResponse,
    EvidenceReviewUpdate,
    ExecutiveKpis,
    FindingInput,
    GraphRequest,
    GraphResult,
    IntegrityVerification,
    PurpleAnalysisRequest,
    ReconRequest,
    ReconResult,
    RemediationCreate,
    RemediationLifecycleUpdate,
    RemediationResponse,
    RemediationSlaItem,
    RiskAcceptanceCreate,
    RiskAcceptanceResponse,
    ScenarioRunRequest,
    ScenarioRunResponse,
    ScenarioSpec,
    TrendPoint,
)
from app.services.ad_detection import detect_ad_findings
from app.services.correlation import correlate_findings
from app.services.expert_ops import (
    campaign_export,
    campaign_timeline,
    create_campaign,
    create_evidence,
    create_remediation,
    detection_tuning_queue,
    evidence_manifest,
    link_run,
    list_campaigns,
    list_evidence,
    list_remediations,
    remediation_sla,
    risk_trend,
)
from app.services.governance import (
    GovernanceViolation,
    coverage_scorecard,
    create_risk_acceptance,
    executive_kpis,
    list_risk_acceptances,
    review_evidence,
    update_campaign,
    update_remediation,
)
from app.services.graph_engine import analyze_attack_graph
from app.services.mitre import all_techniques
from app.services.purple import build_detection_gap_report
from app.services.recon import ReconService
from app.services.report import generate_pdf_report
from app.services.scenario_runner import execute_scenario, list_run_summaries
from app.services.scenarios import list_scenarios


def build_router(settings: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    scope = ScopePolicy.from_strings(settings.allowed_cidr_list)
    recon_service = ReconService(scope, timeout_seconds=settings.recon_timeout_seconds)
    audit = AuditLogger(settings.audit_log_path)
    session_factory = create_session_factory(settings.database_url)
    case_read = require_roles(settings, {"soc_analyst", "remediation_owner", "soc_lead", "platform_admin"})
    case_write = require_roles(settings, {"soc_analyst", "remediation_owner", "soc_lead", "platform_admin"})
    case_lead = require_roles(settings, {"soc_lead", "platform_admin"})

    @router.get("/health")
    def health() -> dict[str, str | bool]:
        return {"status": "ok", "service": settings.app_name, "dry_run_default": settings.dry_run}

    @router.get("/scope")
    def get_scope(_principal: Principal = Depends(case_read)) -> dict[str, list[str] | bool]:  # noqa: B008
        return {"allowed_cidrs": list(scope.allowed_cidrs), "dry_run_default": settings.dry_run}

    @router.get("/techniques")
    def techniques() -> list[dict]:
        return all_techniques()

    @router.get("/plugins")
    def plugins() -> list[dict]:
        return list_plugins()

    @router.get("/scenarios", response_model=list[ScenarioSpec])
    def scenarios() -> list[ScenarioSpec]:
        return list_scenarios()

    @router.get("/runs", response_model=list[AssessmentRunSummary])
    def runs(
        limit: int = 20, _principal: Principal = Depends(case_read)  # noqa: B008
    ) -> list[AssessmentRunSummary]:
        return list_run_summaries(session_factory, max(1, min(limit, 100)))

    @router.post("/scenarios/{scenario_id}/run", response_model=ScenarioRunResponse)
    def scenario_run(
        scenario_id: str, request: ScenarioRunRequest, principal: Principal = Depends(case_write)  # noqa: B008
    ) -> ScenarioRunResponse:
        if request.scenario_id != scenario_id:
            raise HTTPException(status_code=400, detail="scenario_id in path and body must match")
        try:
            result = execute_scenario(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "scenario.completed",
            {
                "run_id": result.run_id,
                "scenario_id": result.scenario_id,
                "dry_run": result.dry_run,
                "finding_count": result.finding_count,
                "coverage_percent": result.coverage_percent,
            },
            actor=principal.actor,
        )
        return result

    @router.get("/campaigns", response_model=list[CampaignResponse])
    def campaigns(_principal: Principal = Depends(case_read)) -> list[CampaignResponse]:  # noqa: B008
        return list_campaigns(session_factory)

    @router.post("/campaigns", response_model=CampaignResponse, status_code=201)
    def campaign_create(
        request: CampaignCreate, principal: Principal = Depends(case_write)  # noqa: B008
    ) -> CampaignResponse:
        result = create_campaign(request, session_factory)
        audit.record(
            "campaign.created",
            {"campaign_id": result.campaign_id, "owner": result.owner},
            actor=principal.actor,
        )
        return result

    @router.post("/campaigns/{campaign_id}/runs/{run_id}", status_code=204)
    def campaign_link_run(
        campaign_id: str, run_id: str, principal: Principal = Depends(case_write)  # noqa: B008
    ) -> None:
        try:
            link_run(campaign_id, run_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record("campaign.run_linked", {"campaign_id": campaign_id, "run_id": run_id}, actor=principal.actor)

    @router.patch("/campaigns/{campaign_id}/lifecycle", response_model=CampaignResponse)
    def campaign_lifecycle(
        campaign_id: str, request: CampaignLifecycleUpdate, principal: Principal = Depends(case_write)  # noqa: B008
    ) -> CampaignResponse:
        try:
            result = update_campaign(campaign_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except GovernanceViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            "campaign.lifecycle_updated",
            {"campaign_id": campaign_id, "status": result.status, "requested_actor": request.actor},
            actor=principal.actor,
        )
        return result

    @router.get("/campaigns/{campaign_id}/timeline", response_model=list[CampaignTimelineEvent])
    def campaign_timeline_route(
        campaign_id: str, _principal: Principal = Depends(case_read)  # noqa: B008
    ) -> list[CampaignTimelineEvent]:
        try:
            return campaign_timeline(campaign_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/integrity/audit", response_model=IntegrityVerification)
    def audit_integrity(_principal: Principal = Depends(case_lead)) -> IntegrityVerification:  # noqa: B008
        return IntegrityVerification(**audit.verify())

    @router.get("/evidence", response_model=list[EvidenceResponse])
    def evidence(
        campaign_id: str | None = None, _principal: Principal = Depends(case_read)  # noqa: B008
    ) -> list[EvidenceResponse]:
        return list_evidence(session_factory, campaign_id)

    @router.get("/evidence/{evidence_id}/manifest", response_model=EvidenceManifest)
    def evidence_manifest_route(
        evidence_id: str, _principal: Principal = Depends(case_read)  # noqa: B008
    ) -> EvidenceManifest:
        try:
            return evidence_manifest(evidence_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.patch("/evidence/{evidence_id}/review", response_model=EvidenceResponse)
    def evidence_review(
        evidence_id: str, request: EvidenceReviewUpdate, principal: Principal = Depends(case_lead)  # noqa: B008
    ) -> EvidenceResponse:
        try:
            result = review_evidence(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except GovernanceViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            "evidence.reviewed",
            {"evidence_id": evidence_id, "status": result.review_status, "reviewer": result.reviewer},
            actor=principal.actor,
        )
        return result

    @router.post("/evidence", response_model=EvidenceResponse, status_code=201)
    def evidence_create(request: EvidenceCreate, principal: Principal = Depends(case_write)) -> EvidenceResponse:  # noqa: B008
        try:
            result = create_evidence(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "evidence.registered",
            {"evidence_id": result.evidence_id, "sha256": result.sha256},
            actor=principal.actor,
        )
        return result

    @router.get("/remediations", response_model=list[RemediationResponse])
    def remediations(
        campaign_id: str | None = None, _principal: Principal = Depends(case_read)  # noqa: B008
    ) -> list[RemediationResponse]:
        return list_remediations(session_factory, campaign_id)

    @router.post("/remediations", response_model=RemediationResponse, status_code=201)
    def remediation_create(
        request: RemediationCreate, principal: Principal = Depends(case_write)  # noqa: B008
    ) -> RemediationResponse:
        try:
            result = create_remediation(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "remediation.created",
            {"remediation_id": result.remediation_id, "priority": result.priority},
            actor=principal.actor,
        )
        return result

    @router.patch("/remediations/{remediation_id}/lifecycle", response_model=RemediationResponse)
    def remediation_lifecycle(
        remediation_id: str, request: RemediationLifecycleUpdate, principal: Principal = Depends(case_write)  # noqa: B008
    ) -> RemediationResponse:
        try:
            result = update_remediation(remediation_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except GovernanceViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            "remediation.lifecycle_updated",
            {"remediation_id": remediation_id, "status": result.status, "actor": request.actor},
            actor=principal.actor,
        )
        return result

    @router.get("/risk-acceptances", response_model=list[RiskAcceptanceResponse])
    def risk_acceptances(_principal: Principal = Depends(case_lead)) -> list[RiskAcceptanceResponse]:  # noqa: B008
        return list_risk_acceptances(session_factory)

    @router.post("/risk-acceptances", response_model=RiskAcceptanceResponse, status_code=201)
    def risk_acceptance_create(
        request: RiskAcceptanceCreate, principal: Principal = Depends(case_lead)  # noqa: B008
    ) -> RiskAcceptanceResponse:
        try:
            result = create_risk_acceptance(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except GovernanceViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit.record(
            "risk.accepted",
            {"acceptance_id": result.acceptance_id, "approver": result.approver, "expires_on": result.expires_on},
            actor=principal.actor,
        )
        return result

    @router.get("/scorecards/coverage", response_model=CoverageScorecard)
    def coverage_scorecard_route(_principal: Principal = Depends(case_read)) -> CoverageScorecard:  # noqa: B008
        return coverage_scorecard(session_factory)

    @router.get("/kpis/executive", response_model=ExecutiveKpis)
    def executive_kpis_route(_principal: Principal = Depends(case_read)) -> ExecutiveKpis:  # noqa: B008
        return executive_kpis(session_factory)

    @router.get("/remediations/sla", response_model=list[RemediationSlaItem])
    def remediation_sla_route(_principal: Principal = Depends(case_read)) -> list[RemediationSlaItem]:  # noqa: B008
        return remediation_sla(session_factory)

    @router.get("/trends/risk", response_model=list[TrendPoint])
    def risk_trends(_principal: Principal = Depends(case_read)) -> list[TrendPoint]:  # noqa: B008
        return risk_trend(session_factory)

    @router.get("/campaigns/{campaign_id}/export", response_model=CampaignExport)
    def campaign_export_route(
        campaign_id: str, _principal: Principal = Depends(case_read)  # noqa: B008
    ) -> CampaignExport:
        try:
            return campaign_export(campaign_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/detection-tuning", response_model=list[DetectionTuningItem])
    def detection_tuning(_principal: Principal = Depends(case_read)) -> list[DetectionTuningItem]:  # noqa: B008
        return detection_tuning_queue(session_factory)

    @router.post("/recon", response_model=ReconResult)
    def recon(request: ReconRequest, principal: Principal = Depends(case_write)) -> ReconResult:  # noqa: B008
        requested_targets = [str(target) for target in request.targets]
        effective_dry_run = settings.dry_run or request.dry_run
        try:
            result = recon_service.run(requested_targets, request.profile, effective_dry_run)
        except ScopeViolation as exc:
            audit.record("recon.rejected", {"targets": requested_targets, "reason": str(exc)}, actor=principal.actor)
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        audit.record(
            "recon.completed",
            {
                "scan_id": result.scan_id,
                "targets": result.targets,
                "profile": request.profile,
                "requested_dry_run": request.dry_run,
                "effective_dry_run": effective_dry_run,
            },
            actor=principal.actor,
        )
        return result

    @router.post("/detections/ad", response_model=list[FindingInput])
    def ad_detections(
        observations: list[dict], _principal: Principal = Depends(case_write)  # noqa: B008
    ) -> list[FindingInput]:
        findings = detect_ad_findings(observations)
        audit.record("ad.detection_analysis", {"observation_count": len(observations), "finding_count": len(findings)})
        return findings

    @router.post("/risk/correlate", response_model=list[CorrelatedRisk])
    def risk_correlate(
        request: CorrelationRequest, _principal: Principal = Depends(case_write)  # noqa: B008
    ) -> list[CorrelatedRisk]:
        results = correlate_findings(request.findings, request.graph)
        audit.record("risk.correlated", {"finding_count": len(request.findings), "result_count": len(results)})
        return results

    @router.post("/graph/analyze", response_model=GraphResult)
    def graph_analyze(
        request: GraphRequest, _principal: Principal = Depends(case_write)  # noqa: B008
    ) -> GraphResult:
        try:
            result = analyze_attack_graph(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        audit.record(
            "graph.analyzed",
            {"source": request.source_node, "target": request.target_node, "node_count": len(request.nodes)},
        )
        return result

    @router.post("/purple/analyze", response_model=DetectionGapReport)
    def purple_analyze(
        request: PurpleAnalysisRequest, _principal: Principal = Depends(case_write)  # noqa: B008
    ) -> DetectionGapReport:
        try:
            report = build_detection_gap_report(request.expected_technique_ids, request.alerts)
        except KeyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        audit.record(
            "purple.coverage_analyzed",
            {
                "run_id": report.run_id,
                "expected_techniques": request.expected_technique_ids,
                "alert_count": len(request.alerts),
                "coverage_percent": report.coverage_percent,
            },
        )
        return report

    @router.post("/reports/pdf")
    def report_pdf(payload: dict, _principal: Principal = Depends(case_read)) -> FileResponse:  # noqa: B008
        findings = [FindingInput.model_validate(item) for item in payload.get("findings", [])]
        coverage_payload = payload.get("coverage")
        coverage = DetectionGapReport.model_validate(coverage_payload) if coverage_payload else None
        event_id = audit.record("report.generated", {"finding_count": len(findings)})
        output = Path(tempfile.gettempdir()) / f"redpath-report-{event_id}.pdf"
        generate_pdf_report(str(output), findings, coverage)
        return FileResponse(output, media_type="application/pdf", filename="redpath-assessment.pdf")

    return router
