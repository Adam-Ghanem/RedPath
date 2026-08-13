from __future__ import annotations

import tempfile
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from app.core.audit import AuditLogger
from app.core.auth import (
    RateLimiter,
    permission_dependency,
    principal_dependency,
    rate_limit_dependency,
    role_dependency,
)
from app.core.config import Settings
from app.core.observability import MetricsRegistry
from app.core.request_context import current_actor, get_principal
from app.core.scope import ScopePolicy, ScopeViolation
from app.db.models import create_session_factory
from app.kernel.contracts import IntegrationAnalysisRequest, IntegrationContext, IntegrationContextRequest
from app.kernel.service import IntegrationKernel
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
from app.schemas.identity import (
    AuthBootstrapRequest,
    AuthLoginRequest,
    AuthMeResponse,
    AuthTokenResponse,
    TenantCreateRequest,
    TenantResponse,
    UserCreateRequest,
    UserResponse,
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
    coverage_scorecard,
    create_risk_acceptance,
    executive_kpis,
    list_risk_acceptances,
    review_evidence,
    update_remediation,
)
from app.services.graph_engine import analyze_attack_graph
from app.services.identity import (
    BootstrapAlreadyCompleted,
    DuplicateIdentity,
    IdentityService,
    InvalidCredentials,
)
from app.services.mitre import all_techniques
from app.services.purple import build_detection_gap_report
from app.services.recon import ReconService
from app.services.report import generate_pdf_report
from app.services.scenario_runner import execute_scenario, list_run_summaries
from app.services.scenarios import list_scenarios


def build_router(settings: Settings, metrics: MetricsRegistry | None = None) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    metrics = metrics or MetricsRegistry()
    scope = ScopePolicy.from_strings(settings.allowed_cidr_list)
    recon_service = ReconService(scope, timeout_seconds=settings.recon_timeout_seconds)
    audit = AuditLogger(settings.audit_log_path)
    integration_kernel = IntegrationKernel(
        scope_validator=lambda targets: scope.validate_targets(list(targets)) if targets else None,
        audit_recorder=audit.record,
    )
    session_factory = create_session_factory(settings.database_url)
    identity = IdentityService(session_factory, settings.auth_bootstrap_token)
    limiter = RateLimiter(settings.rate_limit_requests_per_minute)
    authenticate = principal_dependency(identity, limiter)
    protected_router = APIRouter(prefix="", dependencies=[Depends(authenticate)])

    def record_audit(operation: str, details: dict, *, actor: str | None = None) -> str:
        return audit.record(operation, details, actor=actor or current_actor())

    @router.post(
        "/auth/bootstrap",
        response_model=AuthTokenResponse,
        status_code=201,
        dependencies=[Depends(rate_limit_dependency(limiter))],
    )
    def auth_bootstrap(request: AuthBootstrapRequest) -> AuthTokenResponse:
        if not settings.auth_bootstrap_token:
            raise HTTPException(
                status_code=503, detail="bootstrap is disabled until REDPATH_AUTH_BOOTSTRAP_TOKEN is configured"
            )
        try:
            token = identity.bootstrap(request)
        except BootstrapAlreadyCompleted as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except InvalidCredentials as exc:
            raise HTTPException(status_code=401, detail="invalid bootstrap credentials") from exc
        record_audit(
            "auth.bootstrap_completed",
            {"tenant_slug": request.tenant_slug, "username": request.username},
            actor="bootstrap",
        )
        return token

    @router.post(
        "/auth/token", response_model=AuthTokenResponse, dependencies=[Depends(rate_limit_dependency(limiter))]
    )
    def auth_token(request: AuthLoginRequest) -> AuthTokenResponse:
        try:
            token = identity.login(request)
        except InvalidCredentials as exc:
            raise HTTPException(status_code=401, detail="invalid credentials") from exc
        record_audit("auth.login", {"tenant_slug": token.tenant_slug, "username": token.username}, actor=token.username)
        return token

    @protected_router.get("/auth/me", response_model=AuthMeResponse)
    def auth_me() -> AuthMeResponse:
        principal = get_principal()
        return AuthMeResponse(
            user_id=principal.user_id,
            username=principal.username,
            tenant_id=principal.tenant_id,
            tenant_slug=principal.tenant_slug,
            roles=list(principal.roles),
            session_version=principal.session_version,
        )

    @protected_router.post(
        "/auth/tenants",
        response_model=TenantResponse,
        status_code=201,
        dependencies=[Depends(role_dependency("platform_admin"))],
    )
    def auth_tenant_create(request: TenantCreateRequest) -> TenantResponse:
        try:
            result = identity.create_tenant(request)
        except DuplicateIdentity as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit("auth.tenant_created", {"tenant_id": result.tenant_id, "slug": result.slug})
        return result

    @protected_router.post(
        "/auth/users",
        response_model=UserResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_identity"))],
    )
    def auth_user_create(request: UserCreateRequest) -> UserResponse:
        principal = get_principal()
        try:
            result = identity.create_user(principal, request)
        except DuplicateIdentity as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit("auth.user_created", {"user_id": result.user_id, "roles": result.roles}, actor=current_actor())
        return result

    @protected_router.get(
        "/auth/users",
        response_model=list[UserResponse],
        dependencies=[Depends(permission_dependency("manage_identity"))],
    )
    def auth_users() -> list[UserResponse]:
        principal = get_principal()
        return identity.list_users(principal)

    @router.get("/health")
    def health() -> dict[str, str | bool]:
        return {
            "status": "ok",
            "service": settings.app_name,
            "release": settings.release,
            "environment": settings.environment,
            "dry_run_default": settings.dry_run,
        }

    @router.get("/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "live", "service": settings.app_name}

    @router.get("/health/ready")
    def readiness() -> dict[str, str | dict[str, str]]:
        return {"status": "ready", "checks": {"application": "ok"}}

    @router.get("/metrics", include_in_schema=False)
    def metrics_endpoint() -> PlainTextResponse:
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="metrics are disabled")
        return PlainTextResponse(metrics.prometheus(), media_type="text/plain; version=0.0.4")

    @protected_router.get("/scope", dependencies=[Depends(permission_dependency("read"))])
    def get_scope() -> dict[str, list[str] | bool]:
        return {"allowed_cidrs": list(scope.allowed_cidrs), "dry_run_default": settings.dry_run}

    @protected_router.get("/techniques", dependencies=[Depends(permission_dependency("read"))])
    def techniques() -> list[dict]:
        return all_techniques()

    @protected_router.get("/plugins", dependencies=[Depends(permission_dependency("read"))])
    def plugins() -> list[dict]:
        return list_plugins()

    @protected_router.post(
        "/integrations/{plugin_id}/plan", dependencies=[Depends(permission_dependency("analyze"))]
    )
    def integration_plan(plugin_id: str, request: IntegrationContextRequest):
        principal = get_principal()
        context = IntegrationContext(
            tenant_id=principal.tenant_id,
            actor=principal.username,
            request_id=request.request_id or str(uuid4()),
            targets=request.targets,
            dry_run=settings.dry_run or request.dry_run,
        )
        try:
            return integration_kernel.plan(plugin_id, context)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @protected_router.post(
        "/integrations/{plugin_id}/analyze", dependencies=[Depends(permission_dependency("analyze"))]
    )
    def integration_analyze(plugin_id: str, request: IntegrationAnalysisRequest):
        principal = get_principal()
        context = IntegrationContext(
            tenant_id=principal.tenant_id,
            actor=principal.username,
            request_id=request.request_id or str(uuid4()),
            targets=request.targets,
            dry_run=settings.dry_run or request.dry_run,
        )
        try:
            return integration_kernel.analyze(plugin_id, context, request.observations)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @protected_router.get(
        "/scenarios", response_model=list[ScenarioSpec], dependencies=[Depends(permission_dependency("read"))]
    )
    def scenarios() -> list[ScenarioSpec]:
        return list_scenarios()

    @protected_router.get(
        "/runs", response_model=list[AssessmentRunSummary], dependencies=[Depends(permission_dependency("read"))]
    )
    def runs(limit: int = 20) -> list[AssessmentRunSummary]:
        return list_run_summaries(session_factory, max(1, min(limit, 100)))

    @protected_router.post(
        "/scenarios/{scenario_id}/run",
        response_model=ScenarioRunResponse,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def scenario_run(scenario_id: str, request: ScenarioRunRequest) -> ScenarioRunResponse:
        if request.scenario_id != scenario_id:
            raise HTTPException(status_code=400, detail="scenario_id in path and body must match")
        try:
            result = execute_scenario(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
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

    @protected_router.get(
        "/campaigns", response_model=list[CampaignResponse], dependencies=[Depends(permission_dependency("read"))]
    )
    def campaigns() -> list[CampaignResponse]:
        return list_campaigns(session_factory)

    @protected_router.post(
        "/campaigns",
        response_model=CampaignResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def campaign_create(request: CampaignCreate) -> CampaignResponse:
        result = create_campaign(request, session_factory)
        record_audit("campaign.created", {"campaign_id": result.campaign_id, "owner": result.owner})
        return result

    @protected_router.post(
        "/campaigns/{campaign_id}/runs/{run_id}",
        status_code=204,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def campaign_link_run(campaign_id: str, run_id: str) -> None:
        try:
            link_run(campaign_id, run_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit("campaign.run_linked", {"campaign_id": campaign_id, "run_id": run_id})

    @protected_router.get(
        "/campaigns/{campaign_id}/timeline",
        response_model=list[CampaignTimelineEvent],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def campaign_timeline_route(campaign_id: str) -> list[CampaignTimelineEvent]:
        try:
            return campaign_timeline(campaign_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @protected_router.get(
        "/integrity/audit",
        response_model=IntegrityVerification,
        dependencies=[Depends(permission_dependency("view_audit"))],
    )
    def audit_integrity() -> IntegrityVerification:
        return IntegrityVerification(**audit.verify())

    @protected_router.get(
        "/evidence", response_model=list[EvidenceResponse], dependencies=[Depends(permission_dependency("read"))]
    )
    def evidence(campaign_id: str | None = None) -> list[EvidenceResponse]:
        return list_evidence(session_factory, campaign_id)

    @protected_router.get(
        "/evidence/{evidence_id}/manifest",
        response_model=EvidenceManifest,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def evidence_manifest_route(evidence_id: str) -> EvidenceManifest:
        try:
            return evidence_manifest(evidence_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @protected_router.patch(
        "/evidence/{evidence_id}/review",
        response_model=EvidenceResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def evidence_review(evidence_id: str, request: EvidenceReviewUpdate) -> EvidenceResponse:
        try:
            result = review_evidence(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            "evidence.reviewed",
            {"evidence_id": evidence_id, "status": result.review_status, "reviewer": result.reviewer},
        )
        return result

    @protected_router.post(
        "/evidence",
        response_model=EvidenceResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def evidence_create(request: EvidenceCreate) -> EvidenceResponse:
        try:
            result = create_evidence(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit("evidence.registered", {"evidence_id": result.evidence_id, "sha256": result.sha256})
        return result

    @protected_router.get(
        "/remediations", response_model=list[RemediationResponse], dependencies=[Depends(permission_dependency("read"))]
    )
    def remediations(campaign_id: str | None = None) -> list[RemediationResponse]:
        return list_remediations(session_factory, campaign_id)

    @protected_router.post(
        "/remediations",
        response_model=RemediationResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def remediation_create(request: RemediationCreate) -> RemediationResponse:
        try:
            result = create_remediation(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit("remediation.created", {"remediation_id": result.remediation_id, "priority": result.priority})
        return result

    @protected_router.patch(
        "/remediations/{remediation_id}/lifecycle",
        response_model=RemediationResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def remediation_lifecycle(remediation_id: str, request: RemediationLifecycleUpdate) -> RemediationResponse:
        try:
            result = update_remediation(remediation_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            "remediation.lifecycle_updated",
            {"remediation_id": remediation_id, "status": result.status, "actor": current_actor()},
        )
        return result

    @protected_router.get(
        "/risk-acceptances",
        response_model=list[RiskAcceptanceResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def risk_acceptances() -> list[RiskAcceptanceResponse]:
        return list_risk_acceptances(session_factory)

    @protected_router.post(
        "/risk-acceptances",
        response_model=RiskAcceptanceResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def risk_acceptance_create(request: RiskAcceptanceCreate) -> RiskAcceptanceResponse:
        try:
            result = create_risk_acceptance(request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            "risk.accepted",
            {"acceptance_id": result.acceptance_id, "approver": result.approver, "expires_on": result.expires_on},
        )
        return result

    @protected_router.get(
        "/scorecards/coverage", response_model=CoverageScorecard, dependencies=[Depends(permission_dependency("read"))]
    )
    def coverage_scorecard_route() -> CoverageScorecard:
        return coverage_scorecard(session_factory)

    @protected_router.get(
        "/kpis/executive", response_model=ExecutiveKpis, dependencies=[Depends(permission_dependency("read"))]
    )
    def executive_kpis_route() -> ExecutiveKpis:
        return executive_kpis(session_factory)

    @protected_router.get(
        "/remediations/sla",
        response_model=list[RemediationSlaItem],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def remediation_sla_route() -> list[RemediationSlaItem]:
        return remediation_sla(session_factory)

    @protected_router.get(
        "/trends/risk", response_model=list[TrendPoint], dependencies=[Depends(permission_dependency("read"))]
    )
    def risk_trends() -> list[TrendPoint]:
        return risk_trend(session_factory)

    @protected_router.get(
        "/campaigns/{campaign_id}/export",
        response_model=CampaignExport,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def campaign_export_route(campaign_id: str) -> CampaignExport:
        try:
            return campaign_export(campaign_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @protected_router.get(
        "/detection-tuning",
        response_model=list[DetectionTuningItem],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def detection_tuning() -> list[DetectionTuningItem]:
        return detection_tuning_queue(session_factory)

    @protected_router.post(
        "/recon", response_model=ReconResult, dependencies=[Depends(permission_dependency("analyze"))]
    )
    def recon(request: ReconRequest) -> ReconResult:
        requested_targets = [str(target) for target in request.targets]
        effective_dry_run = settings.dry_run or request.dry_run
        try:
            result = recon_service.run(requested_targets, request.profile, effective_dry_run)
        except ScopeViolation as exc:
            record_audit("recon.rejected", {"targets": requested_targets, "reason": str(exc)})
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        record_audit(
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

    @protected_router.post(
        "/detections/ad", response_model=list[FindingInput], dependencies=[Depends(permission_dependency("analyze"))]
    )
    def ad_detections(observations: list[dict]) -> list[FindingInput]:
        findings = detect_ad_findings(observations)
        record_audit("ad.detection_analysis", {"observation_count": len(observations), "finding_count": len(findings)})
        return findings

    @protected_router.post(
        "/risk/correlate", response_model=list[CorrelatedRisk], dependencies=[Depends(permission_dependency("analyze"))]
    )
    def risk_correlate(request: CorrelationRequest) -> list[CorrelatedRisk]:
        results = correlate_findings(request.findings, request.graph)
        record_audit("risk.correlated", {"finding_count": len(request.findings), "result_count": len(results)})
        return results

    @protected_router.post(
        "/graph/analyze", response_model=GraphResult, dependencies=[Depends(permission_dependency("analyze"))]
    )
    def graph_analyze(request: GraphRequest) -> GraphResult:
        try:
            result = analyze_attack_graph(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record_audit(
            "graph.analyzed",
            {"source": request.source_node, "target": request.target_node, "node_count": len(request.nodes)},
        )
        return result

    @protected_router.post(
        "/purple/analyze", response_model=DetectionGapReport, dependencies=[Depends(permission_dependency("analyze"))]
    )
    def purple_analyze(request: PurpleAnalysisRequest) -> DetectionGapReport:
        try:
            report = build_detection_gap_report(request.expected_technique_ids, request.alerts)
        except KeyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record_audit(
            "purple.coverage_analyzed",
            {
                "run_id": report.run_id,
                "expected_techniques": request.expected_technique_ids,
                "alert_count": len(request.alerts),
                "coverage_percent": report.coverage_percent,
            },
        )
        return report

    @protected_router.post("/reports/pdf", dependencies=[Depends(permission_dependency("read"))])
    def report_pdf(payload: dict) -> FileResponse:
        findings = [FindingInput.model_validate(item) for item in payload.get("findings", [])]
        coverage_payload = payload.get("coverage")
        coverage = DetectionGapReport.model_validate(coverage_payload) if coverage_payload else None
        event_id = record_audit("report.generated", {"finding_count": len(findings)})
        output = Path(tempfile.gettempdir()) / f"redpath-report-{event_id}.pdf"
        generate_pdf_report(str(output), findings, coverage)
        return FileResponse(output, media_type="application/pdf", filename="redpath-assessment.pdf")

    router.include_router(protected_router)
    return router
