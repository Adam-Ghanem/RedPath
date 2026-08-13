from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.core.audit import AuditLogger
from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeViolation
from app.db.models import create_session_factory
from app.plugins.registry import list_plugins
from app.schemas.contracts import (
    AssessmentRunSummary,
    CampaignCreate,
    CampaignExport,
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
from app.schemas.pcap import PcapAnalysisResponse, PcapAnalysisSummary
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
    coverage_scorecard,
    create_risk_acceptance,
    executive_kpis,
    list_risk_acceptances,
    review_evidence,
    update_remediation,
)
from app.services.graph_engine import analyze_attack_graph
from app.services.mitre import all_techniques
from app.services.pcap import PcapFormatError, get_pcap_analysis, list_pcap_analyses, register_pcap_analysis
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

    @router.get("/health")
    def health() -> dict[str, str | bool]:
        return {"status": "ok", "service": settings.app_name, "dry_run_default": settings.dry_run}

    @router.get("/scope")
    def get_scope() -> dict[str, list[str] | bool]:
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
    def runs(limit: int = 20) -> list[AssessmentRunSummary]:
        return list_run_summaries(session_factory, max(1, min(limit, 100)))

    @router.post("/scenarios/{scenario_id}/run", response_model=ScenarioRunResponse)
    def scenario_run(scenario_id: str, request: ScenarioRunRequest) -> ScenarioRunResponse:
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
        )
        return result

    @router.get("/campaigns", response_model=list[CampaignResponse])
    def campaigns() -> list[CampaignResponse]:
        return list_campaigns(session_factory)

    @router.post("/campaigns", response_model=CampaignResponse, status_code=201)
    def campaign_create(request: CampaignCreate) -> CampaignResponse:
        result = create_campaign(request, session_factory)
        audit.record("campaign.created", {"campaign_id": result.campaign_id, "owner": result.owner})
        return result

    @router.post("/campaigns/{campaign_id}/runs/{run_id}", status_code=204)
    def campaign_link_run(campaign_id: str, run_id: str) -> None:
        try:
            link_run(campaign_id, run_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record("campaign.run_linked", {"campaign_id": campaign_id, "run_id": run_id})

    @router.get("/campaigns/{campaign_id}/timeline", response_model=list[CampaignTimelineEvent])
    def campaign_timeline_route(campaign_id: str) -> list[CampaignTimelineEvent]:
        try:
            return campaign_timeline(campaign_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/integrity/audit", response_model=IntegrityVerification)
    def audit_integrity() -> IntegrityVerification:
        return IntegrityVerification(**audit.verify())

    @router.get("/evidence", response_model=list[EvidenceResponse])
    def evidence(campaign_id: str | None = None) -> list[EvidenceResponse]:
        return list_evidence(session_factory, campaign_id)

    @router.get("/evidence/{evidence_id}/manifest", response_model=EvidenceManifest)
    def evidence_manifest_route(evidence_id: str) -> EvidenceManifest:
        try:
            return evidence_manifest(evidence_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.patch("/evidence/{evidence_id}/review", response_model=EvidenceResponse)
    def evidence_review(evidence_id: str, request: EvidenceReviewUpdate) -> EvidenceResponse:
        try:
            result = review_evidence(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "evidence.reviewed",
            {"evidence_id": evidence_id, "status": result.review_status, "reviewer": result.reviewer},
        )
        return result

    @router.post("/evidence", response_model=EvidenceResponse, status_code=201)
    def evidence_create(request: EvidenceCreate) -> EvidenceResponse:
        try:
            result = create_evidence(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record("evidence.registered", {"evidence_id": result.evidence_id, "sha256": result.sha256})
        return result

    def require_pcap_access(role: str | None, tenant_id: str | None) -> str:
        if role not in {"soc_analyst", "incident_commander"}:
            raise HTTPException(status_code=401, detail="PCAP access requires an authenticated SOC role")
        if not tenant_id or len(tenant_id) > 128:
            raise HTTPException(status_code=400, detail="X-Tenant-ID is required and must be at most 128 characters")
        return tenant_id

    @router.post("/pcap/analyses", response_model=PcapAnalysisResponse, status_code=201)
    async def pcap_analysis_create(
        file: UploadFile = File(...),  # noqa: B008
        campaign_id: str | None = Form(default=None),
        x_redpath_role: str | None = Header(default=None, alias="X-RedPath-Role"),
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> PcapAnalysisResponse:
        tenant_id = require_pcap_access(x_redpath_role, x_tenant_id)
        file_name = Path(file.filename or "").name
        if not file_name or file_name != (file.filename or "") or len(file_name) > 255:
            raise HTTPException(status_code=400, detail="file name must be a single safe path component")
        if not file_name.lower().endswith((".pcap", ".pcapng")):
            raise HTTPException(status_code=415, detail="only .pcap and .pcapng evidence is accepted")
        data = await file.read(settings.pcap_max_upload_bytes + 1)
        if len(data) > settings.pcap_max_upload_bytes:
            raise HTTPException(status_code=413, detail="PCAP evidence exceeds the configured upload limit")
        try:
            result = register_pcap_analysis(data, file_name, tenant_id, campaign_id, session_factory)
        except PcapFormatError as exc:
            audit.record("pcap.rejected", {"tenant_id": tenant_id, "file_name": file_name, "reason": str(exc)})
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "pcap.analyzed",
            {
                "analysis_id": result.analysis_id,
                "evidence_id": result.evidence_id,
                "tenant_id": tenant_id,
                "sha256": result.sha256,
                "packet_count": result.packet_count,
            },
        )
        return result

    @router.get("/pcap/analyses", response_model=list[PcapAnalysisSummary])
    def pcap_analyses(
        limit: int = 20,
        x_redpath_role: str | None = Header(default=None, alias="X-RedPath-Role"),
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> list[PcapAnalysisSummary]:
        tenant_id = require_pcap_access(x_redpath_role, x_tenant_id)
        return list_pcap_analyses(tenant_id, session_factory, limit)

    @router.get("/pcap/analyses/{analysis_id}", response_model=PcapAnalysisResponse)
    def pcap_analysis_detail(
        analysis_id: str,
        x_redpath_role: str | None = Header(default=None, alias="X-RedPath-Role"),
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> PcapAnalysisResponse:
        tenant_id = require_pcap_access(x_redpath_role, x_tenant_id)
        try:
            return get_pcap_analysis(analysis_id, tenant_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/remediations", response_model=list[RemediationResponse])
    def remediations(campaign_id: str | None = None) -> list[RemediationResponse]:
        return list_remediations(session_factory, campaign_id)

    @router.post("/remediations", response_model=RemediationResponse, status_code=201)
    def remediation_create(request: RemediationCreate) -> RemediationResponse:
        try:
            result = create_remediation(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record("remediation.created", {"remediation_id": result.remediation_id, "priority": result.priority})
        return result

    @router.patch("/remediations/{remediation_id}/lifecycle", response_model=RemediationResponse)
    def remediation_lifecycle(remediation_id: str, request: RemediationLifecycleUpdate) -> RemediationResponse:
        try:
            result = update_remediation(remediation_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "remediation.lifecycle_updated",
            {"remediation_id": remediation_id, "status": result.status, "actor": request.actor},
        )
        return result

    @router.get("/risk-acceptances", response_model=list[RiskAcceptanceResponse])
    def risk_acceptances() -> list[RiskAcceptanceResponse]:
        return list_risk_acceptances(session_factory)

    @router.post("/risk-acceptances", response_model=RiskAcceptanceResponse, status_code=201)
    def risk_acceptance_create(request: RiskAcceptanceCreate) -> RiskAcceptanceResponse:
        try:
            result = create_risk_acceptance(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit.record(
            "risk.accepted",
            {"acceptance_id": result.acceptance_id, "approver": result.approver, "expires_on": result.expires_on},
        )
        return result

    @router.get("/scorecards/coverage", response_model=CoverageScorecard)
    def coverage_scorecard_route() -> CoverageScorecard:
        return coverage_scorecard(session_factory)

    @router.get("/kpis/executive", response_model=ExecutiveKpis)
    def executive_kpis_route() -> ExecutiveKpis:
        return executive_kpis(session_factory)

    @router.get("/remediations/sla", response_model=list[RemediationSlaItem])
    def remediation_sla_route() -> list[RemediationSlaItem]:
        return remediation_sla(session_factory)

    @router.get("/trends/risk", response_model=list[TrendPoint])
    def risk_trends() -> list[TrendPoint]:
        return risk_trend(session_factory)

    @router.get("/campaigns/{campaign_id}/export", response_model=CampaignExport)
    def campaign_export_route(campaign_id: str) -> CampaignExport:
        try:
            return campaign_export(campaign_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/detection-tuning", response_model=list[DetectionTuningItem])
    def detection_tuning() -> list[DetectionTuningItem]:
        return detection_tuning_queue(session_factory)

    @router.post("/recon", response_model=ReconResult)
    def recon(request: ReconRequest) -> ReconResult:
        requested_targets = [str(target) for target in request.targets]
        effective_dry_run = settings.dry_run or request.dry_run
        try:
            result = recon_service.run(requested_targets, request.profile, effective_dry_run)
        except ScopeViolation as exc:
            audit.record("recon.rejected", {"targets": requested_targets, "reason": str(exc)})
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
        )
        return result

    @router.post("/detections/ad", response_model=list[FindingInput])
    def ad_detections(observations: list[dict]) -> list[FindingInput]:
        findings = detect_ad_findings(observations)
        audit.record("ad.detection_analysis", {"observation_count": len(observations), "finding_count": len(findings)})
        return findings

    @router.post("/risk/correlate", response_model=list[CorrelatedRisk])
    def risk_correlate(request: CorrelationRequest) -> list[CorrelatedRisk]:
        results = correlate_findings(request.findings, request.graph)
        audit.record("risk.correlated", {"finding_count": len(request.findings), "result_count": len(results)})
        return results

    @router.post("/graph/analyze", response_model=GraphResult)
    def graph_analyze(request: GraphRequest) -> GraphResult:
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
    def purple_analyze(request: PurpleAnalysisRequest) -> DetectionGapReport:
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
    def report_pdf(payload: dict) -> FileResponse:
        findings = [FindingInput.model_validate(item) for item in payload.get("findings", [])]
        coverage_payload = payload.get("coverage")
        coverage = DetectionGapReport.model_validate(coverage_payload) if coverage_payload else None
        event_id = audit.record("report.generated", {"finding_count": len(findings)})
        output = Path(tempfile.gettempdir()) / f"redpath-report-{event_id}.pdf"
        generate_pdf_report(str(output), findings, coverage)
        return FileResponse(output, media_type="application/pdf", filename="redpath-assessment.pdf")

    return router
