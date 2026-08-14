from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse

from app.core.audit import AuditLogger
from app.core.auth import (
    MfaStepUpPolicy,
    RateLimiter,
    build_authentication_provider,
    permission_dependency,
    principal_dependency,
    rate_limit_dependency,
    role_dependency,
)
from app.core.config import Settings
from app.core.observability import MetricsRegistry
from app.core.request_context import current_actor, get_principal, maybe_principal
from app.core.scope import ScopePolicy, ScopeViolation
from app.db.models import Asset, Campaign, EvidenceItem, create_session_factory
from app.kernel.contracts import (
    CapabilityNegotiation,
    CapabilityNegotiationRequest,
    IntegrationAnalysisRequest,
    IntegrationContext,
    IntegrationContextRequest,
    IntegrationKernelError,
    Page,
    PaginationRequest,
    PluginCatalogPage,
)
from app.kernel.service import IntegrationKernel
from app.models.telemetry import (
    TelemetryDetectionRequest,
    TelemetryDetectionResponse,
    TelemetryEvidenceProjection,
    TelemetryHealthResponse,
    TelemetryIngestionResponse,
    TelemetryListResponse,
    TelemetryQuery,
)
from app.platform import HealthCheck, HealthContract, HealthStatus, LivenessContract, ReadinessContract
from app.plugins.registry import list_plugins
from app.schemas.contracts import (
    AssessmentRunSummary,
    AttackPathAnalysisRequest,
    AttackPathAnalysisResponse,
    CampaignCreate,
    CampaignExport,
    CampaignResponse,
    CampaignTimelineEvent,
    CaseStatusUpdate,
    CopilotExplainRequest,
    CopilotExplanationResponse,
    CorrelatedRisk,
    CorrelationRequest,
    CoverageScorecard,
    DetectionCoverageReport,
    DetectionCoverageRequest,
    DetectionEvaluationRequest,
    DetectionEvaluationResponse,
    DetectionGapReport,
    DetectionLifecycleGateRequest,
    DetectionLifecycleGateResponse,
    DetectionRule,
    DetectionRuleCreate,
    DetectionTuningItem,
    DiscoveryJobCreate,
    DiscoveryJobStatus,
    EvidenceCreate,
    EvidenceCustodyEventResponse,
    EvidenceCustodyVerifyRequest,
    EvidenceDeletionDecisionRequest,
    EvidenceDeletionRequestCreate,
    EvidenceDeletionRequestResponse,
    EvidenceIntegrityResponse,
    EvidenceLegalHoldRequest,
    EvidenceLegalHoldResponse,
    EvidenceManifest,
    EvidencePrivacySummary,
    EvidenceResponse,
    EvidenceRetentionDecisionRequest,
    EvidenceRetentionDecisionResponse,
    EvidenceReviewUpdate,
    ExecutiveKpis,
    FindingInput,
    GovernanceHistoryEvent,
    GraphRequest,
    GraphResult,
    IntegrityVerification,
    InventoryAsset,
    NormalizedRegressionReport,
    NormalizedRegressionRequest,
    PurpleAnalysisRequest,
    ReconRequest,
    ReconResult,
    RegressionReport,
    RegressionRunRequest,
    RemediationAssignmentUpdate,
    RemediationCreate,
    RemediationLifecycleUpdate,
    RemediationResponse,
    RemediationSlaEscalation,
    RemediationSlaItem,
    RemediationVerificationUpdate,
    RiskAcceptanceCreate,
    RiskAcceptanceDecisionRequest,
    RiskAcceptanceResponse,
    ScenarioRunRequest,
    ScenarioRunResponse,
    ScenarioSpec,
    TrendPoint,
)
from app.schemas.identity import (
    AccessRequestCreateRequest,
    AccessRequestDecisionRequest,
    AccessRequestResponse,
    AuthBootstrapRequest,
    AuthLoginRequest,
    AuthMeResponse,
    AuthSessionRevokeResponse,
    AuthTokenResponse,
    LeastPrivilegeReviewResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    RevocationVerificationResponse,
    ServiceAccountCreateRequest,
    ServiceAccountInventoryItem,
    ServiceAccountResponse,
    ServiceAccountTokenResponse,
    SessionRiskResponse,
    TenantCreateRequest,
    TenantResponse,
    UserCreateRequest,
    UserResponse,
)
from app.schemas.pcap import (
    PcapAnalysisResponse,
    PcapAnalysisSummary,
    PcapDeletionCheckResponse,
    PcapDrilldownResponse,
    PcapEvidenceView,
    PcapLifecycleResponse,
    PcapManifestVerification,
)
from app.services.access_governance import (
    AccessGovernanceService,
    AccessRequestInvalid,
    AccessRequestNotFound,
)
from app.services.ad_detection import detect_ad_findings
from app.services.attack_path_risk import analyze_attack_path_risk, to_persistence_record
from app.services.case_governance import (
    list_custody_history,
    list_governance_history,
    verify_evidence_custody,
)
from app.services.case_ops import list_cases, update_case_status
from app.services.copilot_explanation import build_copilot_service
from app.services.copilot_sources import CopilotSourceNotFound, register_attack_path_analysis, resolve_copilot_source
from app.services.correlation import correlate_findings
from app.services.detection_framework import DetectionRuleCatalog
from app.services.detection_lifecycle import DetectionLifecycleService
from app.services.discovery_jobs import (
    DiscoveryJobNotFound,
    DiscoveryJobService,
    DiscoveryRateLimitExceeded,
)
from app.services.evidence_governance import (
    EvidenceGovernanceViolation,
    create_retention_decision,
    decide_deletion,
    get_legal_hold,
    list_retention_decisions,
    privacy_summary,
    request_deletion,
    reverify_integrity,
    set_legal_hold,
)
from app.services.expert_ops import (
    assign_remediation,
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
    remediation_escalations,
    remediation_sla,
    risk_trend,
)
from app.services.governance import (
    coverage_scorecard,
    create_risk_acceptance,
    decide_risk_acceptance,
    executive_kpis,
    expire_risk_acceptance,
    list_risk_acceptances,
    review_evidence,
    update_remediation,
    verify_remediation,
)
from app.services.graph_engine import analyze_attack_graph
from app.services.identity import (
    BootstrapAlreadyCompleted,
    DuplicateIdentity,
    IdentityService,
    InvalidCredentials,
)
from app.services.mitre import all_techniques
from app.services.pcap import (
    PcapFormatError,
    get_pcap_analysis,
    get_pcap_evidence_view_by_evidence,
    list_pcap_analyses,
    register_pcap_analysis,
)
from app.services.pcap_lifecycle import (
    PcapLifecycleViolation,
    check_pcap_deletion,
    get_pcap_drilldown,
    get_pcap_lifecycle,
    get_pcap_manifest,
    list_pcap_lifecycles,
    quarantine_pcap,
    safe_parse_failure,
)
from app.services.purple import build_detection_gap_report
from app.services.recon import ReconService
from app.services.report import generate_pdf_report
from app.services.scenario_runner import execute_scenario, list_run_summaries
from app.services.scenarios import list_scenarios
from app.services.service_accounts import (
    ServiceAccountError,
    ServiceAccountNotFound,
    ServiceAccountService,
)
from app.services.siem_ingestion import SiemIngestionService, list_telemetry
from app.services.telemetry_correlation import (
    evaluate_telemetry,
    health_diagnostics,
    load_telemetry,
    project_case_evidence,
)
from app.services.telemetry_resilience import TelemetryResilienceStore
from app.services.wazuh import WazuhIndexerClient


def build_router(
    settings: Settings,
    metrics: MetricsRegistry | None = None,
    *,
    audit: AuditLogger | None = None,
    oidc_verifier=None,
    risk_evaluator=None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    metrics = metrics or MetricsRegistry()
    scope = ScopePolicy.from_strings(settings.allowed_cidr_list)
    recon_service = ReconService(scope, timeout_seconds=settings.recon_timeout_seconds)
    audit = audit or AuditLogger(settings.audit_log_path)
    integration_kernel = IntegrationKernel(
        scope_validator=lambda targets: scope.validate_targets(list(targets)) if targets else None,
        audit_recorder=audit.record,
    )
    session_factory = create_session_factory(settings.database_url)
    identity = IdentityService(session_factory, settings.auth_bootstrap_token)
    service_accounts = ServiceAccountService(
        session_factory,
        max_ttl_days=settings.service_account_max_ttl_days,
        token_ttl_minutes=settings.service_account_token_ttl_minutes,
    )
    access_governance = AccessGovernanceService(
        session_factory,
        risk_evaluator=risk_evaluator,
    )
    limiter = RateLimiter(settings.rate_limit_requests_per_minute)
    copilot_limiter = RateLimiter(settings.ai_copilot_requests_per_minute)
    copilot_service = build_copilot_service(settings)
    provider = build_authentication_provider(
        settings.auth_provider,
        identity,
        service_accounts=service_accounts,
        oidc_verifier=oidc_verifier,
    )
    step_up_policy = MfaStepUpPolicy(settings.auth_mfa_required_permission_list)
    authenticate = principal_dependency(identity, limiter, provider=provider)
    protected_router = APIRouter(prefix="", dependencies=[Depends(authenticate)])

    def record_audit(operation: str, details: dict, *, actor: str | None = None) -> str:
        principal = maybe_principal()
        enriched = dict(details)
        if principal:
            enriched.setdefault("tenant_id", principal.tenant_id)
        return audit.record(operation, enriched, actor=actor or current_actor())

    def assess_with_copilot(request: CopilotExplainRequest) -> CopilotExplanationResponse:
        principal = get_principal()
        try:
            source = resolve_copilot_source(
                request,
                tenant_id=principal.tenant_id,
                session_factory=session_factory,
            )
            return copilot_service.explain(source, authorized_tenant_id=principal.tenant_id)
        except CopilotSourceNotFound as exc:
            raise HTTPException(status_code=404, detail="requested AI source was not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="requested AI source is not authorized") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    def raise_integration_error(exc: IntegrationKernelError) -> None:
        detail = exc.error.model_dump(mode="json")
        detail.update(exc.error.details)
        raise HTTPException(status_code=exc.status_code, detail=detail) from exc

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
            auth_method=principal.auth_method,
            mfa_verified=principal.mfa_verified,
            step_up_expires_at=principal.step_up_expires_at,
        )

    @protected_router.post("/auth/logout", response_model=AuthSessionRevokeResponse)
    def auth_logout(request: Request) -> AuthSessionRevokeResponse:
        raw_token = getattr(request.state, "access_token", None)
        if not isinstance(raw_token, str) or not raw_token:
            raise HTTPException(status_code=401, detail="authentication required")
        revoked = identity.revoke(raw_token)
        record_audit("auth.logout", {"revoked_sessions": int(revoked)})
        return AuthSessionRevokeResponse(revoked_sessions=int(revoked))

    @protected_router.post("/auth/sessions/revoke-all", response_model=AuthSessionRevokeResponse)
    def auth_revoke_all_sessions() -> AuthSessionRevokeResponse:
        principal = get_principal()
        revoked = identity.revoke_all(principal)
        record_audit("auth.sessions_revoked", {"revoked_sessions": revoked})
        return AuthSessionRevokeResponse(revoked_sessions=revoked)

    @protected_router.post(
        "/auth/service-accounts",
        response_model=ServiceAccountTokenResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def service_account_create(request: ServiceAccountCreateRequest) -> ServiceAccountTokenResponse:
        principal = get_principal()
        try:
            result = service_accounts.create(principal, request)
        except ServiceAccountError as exc:
            raise HTTPException(status_code=409, detail="service-account request rejected") from exc
        record_audit(
            "auth.service_account_created",
            {"service_account_id": result.service_account.service_account_id, "scopes": result.service_account.scopes},
        )
        return result

    @protected_router.get(
        "/auth/service-accounts",
        response_model=list[ServiceAccountResponse],
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def service_account_list() -> list[ServiceAccountResponse]:
        return service_accounts.list(get_principal())

    @protected_router.post(
        "/auth/service-accounts/{service_account_id}/rotate",
        response_model=ServiceAccountTokenResponse,
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def service_account_rotate(service_account_id: str) -> ServiceAccountTokenResponse:
        try:
            result = service_accounts.rotate(get_principal(), service_account_id)
        except ServiceAccountNotFound as exc:
            raise HTTPException(status_code=404, detail="service account not found") from exc
        record_audit(
            "auth.service_account_rotated",
            {
                "service_account_id": result.service_account.service_account_id,
                "token_version": result.service_account.token_version,
            },
        )
        return result

    @protected_router.post(
        "/auth/service-accounts/{service_account_id}/revoke",
        response_model=ServiceAccountResponse,
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def service_account_revoke(service_account_id: str) -> ServiceAccountResponse:
        try:
            result = service_accounts.revoke(get_principal(), service_account_id)
        except ServiceAccountNotFound as exc:
            raise HTTPException(status_code=404, detail="service account not found") from exc
        record_audit(
            "auth.service_account_revoked",
            {"service_account_id": result.service_account_id, "token_version": result.token_version},
        )
        return result

    @protected_router.post(
        "/auth/access-governance/policy-evaluate",
        response_model=PolicyEvaluationResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def access_policy_evaluate(request: PolicyEvaluationRequest) -> PolicyEvaluationResponse:
        principal = get_principal()
        result = access_governance.evaluate_policy(principal, request)
        record_audit(
            "authz.policy_evaluated",
            {
                "allowed": result.allowed,
                "reason_code": result.reason_code,
                "requested_scope_count": len(result.effective_scopes),
            },
        )
        return result

    @protected_router.post(
        "/auth/access-requests",
        response_model=AccessRequestResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def access_request_create(request: AccessRequestCreateRequest) -> AccessRequestResponse:
        try:
            result = access_governance.create_request(get_principal(), request)
        except AccessRequestInvalid as exc:
            raise HTTPException(status_code=409, detail="access request rejected") from exc
        record_audit(
            "authz.jit_request_created",
            {"request_id": result.request_id, "requested_scope_count": len(result.requested_scopes)},
        )
        return result

    @protected_router.get(
        "/auth/access-requests",
        response_model=list[AccessRequestResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def access_request_list() -> list[AccessRequestResponse]:
        principal = get_principal()
        include_all = principal.has_role("platform_admin") or principal.has_role("tenant_admin")
        return access_governance.list_requests(principal, include_all=include_all)

    @protected_router.post(
        "/auth/access-requests/{request_id}/decision",
        response_model=AccessRequestResponse,
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def access_request_decide(
        request_id: str,
        request: AccessRequestDecisionRequest,
    ) -> AccessRequestResponse:
        try:
            result = access_governance.decide_request(get_principal(), request_id, request)
        except AccessRequestNotFound as exc:
            raise HTTPException(status_code=404, detail="access request not found") from exc
        except AccessRequestInvalid as exc:
            raise HTTPException(status_code=409, detail="access request rejected") from exc
        record_audit(
            "authz.jit_request_decided",
            {"request_id": result.request_id, "status": result.status},
        )
        return result

    @protected_router.get(
        "/auth/access-governance/service-accounts",
        response_model=list[ServiceAccountInventoryItem],
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def access_service_account_inventory() -> list[ServiceAccountInventoryItem]:
        return access_governance.service_account_inventory(get_principal())

    @protected_router.get(
        "/auth/access-governance/service-accounts/{service_account_id}/revocation",
        response_model=RevocationVerificationResponse,
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def access_service_account_revocation(service_account_id: str) -> RevocationVerificationResponse:
        try:
            result = access_governance.verify_revocation(get_principal(), service_account_id)
        except AccessRequestNotFound as exc:
            raise HTTPException(status_code=404, detail="service account not found") from exc
        record_audit(
            "authz.service_account_revocation_verified",
            {
                "service_account_id": result.service_account_id,
                "active_token_count": result.active_token_count,
                "all_prior_tokens_revoked": result.all_prior_tokens_revoked,
            },
        )
        return result

    @protected_router.get(
        "/auth/access-governance/session-risk",
        response_model=SessionRiskResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def access_session_risk(request: Request) -> SessionRiskResponse:
        principal = get_principal()
        result = access_governance.session_risk(
            principal,
            {"source": request.headers.get("x-client-source", "unknown")},
        )
        record_audit(
            "authz.session_risk_evaluated",
            {"risk_level": result.risk_level, "requires_step_up": result.requires_step_up},
        )
        return result

    @protected_router.get(
        "/auth/access-governance/least-privilege-review",
        response_model=LeastPrivilegeReviewResponse,
        dependencies=[Depends(permission_dependency("manage_identity", step_up_policy=step_up_policy))],
    )
    def access_least_privilege_review() -> LeastPrivilegeReviewResponse:
        result = access_governance.least_privilege_review(get_principal())
        record_audit(
            "authz.least_privilege_review_exported",
            {"account_count": len(result.items)},
        )
        return result

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
    discovery_jobs = DiscoveryJobService(
        recon_service,
        session_factory,
        audit,
        max_workers=settings.recon_max_workers,
        max_jobs_per_minute=settings.discovery_max_jobs_per_minute,
        retention_hours=settings.discovery_job_retention_hours,
        retention_max=settings.discovery_job_retention_max,
        recovery_timeout_seconds=settings.discovery_recovery_timeout_seconds,
        lease_seconds=settings.discovery_lease_seconds,
        retry_budget=settings.discovery_retry_budget,
        checkpoint_max_bytes=settings.discovery_checkpoint_max_bytes,
        result_max_bytes=settings.discovery_result_max_bytes,
    )
    telemetry_resilience = TelemetryResilienceStore(
        session_factory,
        metrics=metrics,
        dead_letter_retention_hours=settings.siem_dead_letter_retention_hours,
        dead_letter_max_metadata_bytes=settings.siem_dead_letter_metadata_max_bytes,
        lag_warning_seconds=settings.siem_lag_warning_seconds,
        retention_max_dead_letters=settings.siem_dead_letter_retention_max,
    )
    siem_client = WazuhIndexerClient(
        settings.wazuh_indexer_url,
        settings.wazuh_username,
        settings.wazuh_password,
        verify_tls=settings.wazuh_verify_tls,
        timeout_seconds=settings.siem_request_timeout_seconds,
        connector_role=settings.siem_connector_role,
        read_only=settings.siem_connector_read_only,
        checkpoint_max_bytes=settings.siem_checkpoint_max_bytes,
    )
    siem_service = SiemIngestionService(
        siem_client,
        session_factory,
        max_query_window_hours=settings.siem_max_query_window_hours,
        resilience=telemetry_resilience,
        metrics=metrics,
    )
    detection_catalog = DetectionRuleCatalog()
    detection_lifecycle = DetectionLifecycleService(detection_catalog)

    @router.get("/health", response_model=HealthContract)
    def health() -> HealthContract:
        return HealthContract(
            service=settings.app_name,
            release=settings.release,
            environment=settings.environment,
            dry_run_default=settings.dry_run,
        )

    @router.get("/health/live", response_model=LivenessContract)
    def liveness() -> LivenessContract:
        return LivenessContract(service=settings.app_name)

    @router.get("/health/ready", response_model=ReadinessContract)
    def readiness() -> ReadinessContract:
        return ReadinessContract(
            status="ready",
            service=settings.app_name,
            checks={"application": HealthCheck(status=HealthStatus.OK)},
        )

    @router.get("/metrics", include_in_schema=False)
    def metrics_endpoint() -> PlainTextResponse:
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="metrics are disabled")
        return PlainTextResponse(metrics.prometheus(), media_type="text/plain; version=0.0.4")

    @protected_router.post(
        "/siem/telemetry/ingest",
        response_model=TelemetryIngestionResponse,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    async def siem_telemetry_ingest(request: TelemetryQuery) -> TelemetryIngestionResponse:
        principal = get_principal()
        if request.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=403, detail="Telemetry tenant does not match authenticated tenant")
        try:
            result = await siem_service.ingest(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="Wazuh read failed") from exc
        audit.record(
            "siem.telemetry_ingested",
            {
                "tenant_id": result.tenant_id,
                "run_id": result.run_id,
                "fetched_count": result.fetched_count,
                "stored_count": result.stored_count,
                "deduplicated_count": result.deduplicated_count,
            },
            actor=principal.username,
        )
        return result

    @protected_router.get(
        "/siem/telemetry",
        response_model=TelemetryListResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def siem_telemetry_list(
        start: datetime = Query(...),  # noqa: B008
        end: datetime = Query(...),  # noqa: B008
        limit: int = Query(default=200, ge=1, le=1000),  # noqa: B008
    ) -> TelemetryListResponse:
        principal = get_principal()
        if start.tzinfo is None or end.tzinfo is None:
            raise HTTPException(status_code=422, detail="telemetry query bounds must be timezone-aware")
        if start >= end:
            raise HTTPException(status_code=422, detail="telemetry query start must be before end")
        try:
            result = list_telemetry(
                session_factory,
                tenant_id=principal.tenant_id,
                start=start.astimezone(timezone.utc),
                end=end.astimezone(timezone.utc),
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        audit.record(
            "siem.telemetry_listed",
            {"tenant_id": principal.tenant_id, "event_count": len(result.events)},
            actor=principal.username,
        )
        return result

    @protected_router.post(
        "/siem/telemetry/detections/evaluate",
        response_model=TelemetryDetectionResponse,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def siem_telemetry_detection(request: TelemetryDetectionRequest) -> TelemetryDetectionResponse:
        principal = get_principal()
        try:
            result = evaluate_telemetry(
                session_factory,
                tenant_id=principal.tenant_id,
                request=request,
                catalog=detection_catalog,
                metrics=metrics,
            )
        except (KeyError, ValueError) as exc:
            status_code = 404 if isinstance(exc, KeyError) else 422
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        record_audit(
            "siem.telemetry_detection_evaluated",
            {
                "tenant_id": principal.tenant_id,
                "event_count": result.event_count,
                "match_count": len(result.evaluation.get("matches", [])),
            },
        )
        return result

    @protected_router.get(
        "/siem/telemetry/evidence",
        response_model=list[TelemetryEvidenceProjection],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def siem_telemetry_evidence(
        start: datetime = Query(...),  # noqa: B008
        end: datetime = Query(...),  # noqa: B008
        limit: int = Query(default=200, ge=1, le=1000),  # noqa: B008
    ) -> list[TelemetryEvidenceProjection]:
        principal = get_principal()
        try:
            events = load_telemetry(
                session_factory,
                tenant_id=principal.tenant_id,
                start=start,
                end=end,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        projections = project_case_evidence(events)
        record_audit(
            "siem.telemetry_evidence_projected",
            {"tenant_id": principal.tenant_id, "event_count": len(projections)},
        )
        return projections

    @protected_router.get(
        "/siem/telemetry/health",
        response_model=TelemetryHealthResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def siem_telemetry_health() -> TelemetryHealthResponse:
        principal = get_principal()
        result = health_diagnostics(
            session_factory,
            tenant_id=principal.tenant_id,
            resilience=telemetry_resilience,
            lag_warning_seconds=settings.siem_lag_warning_seconds,
        )
        record_audit(
            "siem.telemetry_health_read",
            {
                "tenant_id": principal.tenant_id,
                "status": result.status,
                "total_runs": result.total_runs,
                "total_events": result.total_events,
            },
        )
        return result

    @protected_router.get("/scope", dependencies=[Depends(permission_dependency("read"))])
    def get_scope() -> dict[str, list[str] | bool]:
        return {"allowed_cidrs": list(scope.allowed_cidrs), "dry_run_default": settings.dry_run}

    @protected_router.get("/techniques", dependencies=[Depends(permission_dependency("read"))])
    def techniques() -> list[dict]:
        return all_techniques()

    @protected_router.get("/plugins", dependencies=[Depends(permission_dependency("read"))])
    def plugins() -> list[dict]:
        return list_plugins()

    @protected_router.get(
        "/plugins/catalog",
        response_model=PluginCatalogPage,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def plugin_catalog(
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = Query(default=None, min_length=1, max_length=6, pattern=r"^\d{1,6}$"),
    ) -> PluginCatalogPage:
        return integration_kernel.registry.catalog_page(PaginationRequest(limit=limit, cursor=cursor))

    @protected_router.post(
        "/integrations/{plugin_id}/negotiate",
        response_model=CapabilityNegotiation,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def integration_negotiate(plugin_id: str, request: CapabilityNegotiationRequest) -> CapabilityNegotiation:
        principal = get_principal()
        return integration_kernel.negotiate_request(
            plugin_id,
            request.model_copy(update={"request_id": request.request_id or str(uuid4())}),
            tenant_id=principal.tenant_id,
            actor=principal.username,
        )

    @protected_router.post(
        "/integrations/{plugin_id}/plan", dependencies=[Depends(permission_dependency("analyze"))]
    )
    def integration_plan(plugin_id: str, request: IntegrationContextRequest):
        principal = get_principal()
        context = IntegrationContext(
            tenant_id=principal.tenant_id,
            actor=principal.username,
            request_id=request.request_id or str(uuid4()),
            contract_version=request.contract_version,
            requested_capabilities=request.requested_capabilities,
            targets=request.targets,
            dry_run=settings.dry_run or request.dry_run,
        )
        try:
            return integration_kernel.plan(plugin_id, context)
        except IntegrationKernelError as exc:
            raise_integration_error(exc)
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
            contract_version=request.contract_version,
            requested_capabilities=request.requested_capabilities,
            targets=request.targets,
            dry_run=settings.dry_run or request.dry_run,
        )
        try:
            return integration_kernel.analyze(plugin_id, context, request.observations)
        except IntegrationKernelError as exc:
            raise_integration_error(exc)
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

    @protected_router.get(
        "/cases", response_model=list[CampaignResponse], dependencies=[Depends(permission_dependency("read"))]
    )
    def cases() -> list[CampaignResponse]:
        return list_cases(session_factory)

    @protected_router.post(
        "/cases",
        response_model=CampaignResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def case_create(request: CampaignCreate) -> CampaignResponse:
        result = create_campaign(request, session_factory)
        record_audit("case.created", {"case_id": result.campaign_id})
        return result

    @protected_router.patch(
        "/cases/{case_id}/status",
        response_model=CampaignResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def case_status(case_id: str, request: CaseStatusUpdate) -> CampaignResponse:
        try:
            result = update_case_status(case_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit("case.status_changed", {"case_id": case_id, "status": result.status})
        return result

    @protected_router.get(
        "/cases/{case_id}/governance-history",
        response_model=list[GovernanceHistoryEvent],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def case_governance_history(case_id: str) -> list[GovernanceHistoryEvent]:
        try:
            history = list_governance_history(case_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if not history:
            tenant_id = get_principal().tenant_id
            with session_factory() as session:
                known_case = session.query(Campaign).filter_by(id=case_id, tenant_id=tenant_id).first()
            if known_case is None:
                raise HTTPException(status_code=404, detail=f"Unknown case: {case_id}")
        return history

    @protected_router.get(
        "/cases/{case_id}/custody-history",
        response_model=list[EvidenceCustodyEventResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def case_custody_history(case_id: str) -> list[EvidenceCustodyEventResponse]:
        try:
            custody = list_custody_history(case_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if not custody:
            tenant_id = get_principal().tenant_id
            with session_factory() as session:
                known_case = session.query(Campaign).filter_by(id=case_id, tenant_id=tenant_id).first()
            if known_case is None:
                raise HTTPException(status_code=404, detail=f"Unknown case: {case_id}")
        return custody

    @protected_router.get(
        "/cases/{case_id}/evidence",
        response_model=list[EvidenceResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def case_evidence(case_id: str) -> list[EvidenceResponse]:
        try:
            return list_evidence(session_factory, case_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @protected_router.get(
        "/cases/{case_id}/remediations",
        response_model=list[RemediationResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def case_remediations(case_id: str) -> list[RemediationResponse]:
        try:
            return list_remediations(session_factory, case_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @protected_router.get(
        "/cases/{case_id}/export",
        response_model=CampaignExport,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def case_export(case_id: str) -> CampaignExport:
        try:
            return campaign_export(case_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

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
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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

    @protected_router.post(
        "/evidence/{evidence_id}/custody",
        response_model=EvidenceCustodyEventResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def evidence_custody(evidence_id: str, request: EvidenceCustodyVerifyRequest) -> EvidenceCustodyEventResponse:
        try:
            result = verify_evidence_custody(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "evidence.custody_verified",
            {"evidence_id": evidence_id, "decision": result.decision, "manifest_sha256": result.manifest_sha256},
        )
        return result

    @protected_router.post(
        "/evidence/{evidence_id}/integrity/reverify",
        response_model=EvidenceIntegrityResponse,
        dependencies=[Depends(permission_dependency("view_audit"))],
    )
    def evidence_integrity_reverify(evidence_id: str) -> EvidenceIntegrityResponse:
        try:
            result = reverify_integrity(evidence_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc
        record_audit(
            "evidence.integrity_reverified",
            {"evidence_id": evidence_id, "valid": result.valid, "failure_code": result.failure_code},
        )
        return result

    @protected_router.post(
        "/evidence/{evidence_id}/legal-hold",
        response_model=EvidenceLegalHoldResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def evidence_legal_hold(
        evidence_id: str,
        request: EvidenceLegalHoldRequest,
    ) -> EvidenceLegalHoldResponse:
        try:
            result = set_legal_hold(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc
        record_audit(
            "evidence.legal_hold_changed",
            {"evidence_id": evidence_id, "active": result.active},
        )
        return result

    @protected_router.get(
        "/evidence/{evidence_id}/legal-hold",
        response_model=EvidenceLegalHoldResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def evidence_legal_hold_get(evidence_id: str) -> EvidenceLegalHoldResponse:
        try:
            return get_legal_hold(evidence_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc

    @protected_router.post(
        "/evidence/{evidence_id}/retention-decision",
        response_model=EvidenceRetentionDecisionResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def evidence_retention_decision(
        evidence_id: str,
        request: EvidenceRetentionDecisionRequest,
    ) -> EvidenceRetentionDecisionResponse:
        try:
            result = create_retention_decision(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc
        record_audit(
            "evidence.retention_decided",
            {"evidence_id": evidence_id, "decision": result.decision},
        )
        return result

    @protected_router.get(
        "/evidence/{evidence_id}/retention-history",
        response_model=list[EvidenceRetentionDecisionResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def evidence_retention_history(
        evidence_id: str,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> list[EvidenceRetentionDecisionResponse]:
        try:
            return list_retention_decisions(evidence_id, session_factory, limit=limit)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc

    @protected_router.post(
        "/evidence/{evidence_id}/deletion-request",
        response_model=EvidenceDeletionRequestResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def evidence_deletion_request(
        evidence_id: str,
        request: EvidenceDeletionRequestCreate,
    ) -> EvidenceDeletionRequestResponse:
        try:
            result = request_deletion(evidence_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc
        except EvidenceGovernanceViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit("evidence.deletion_requested", {"evidence_id": evidence_id})
        return result

    @protected_router.post(
        "/evidence/{evidence_id}/deletion-request/{request_id}/decision",
        response_model=EvidenceDeletionRequestResponse,
        dependencies=[Depends(permission_dependency("view_audit"))],
    )
    def evidence_deletion_decision(
        evidence_id: str,
        request_id: str,
        request: EvidenceDeletionDecisionRequest,
    ) -> EvidenceDeletionRequestResponse:
        try:
            result = decide_deletion(evidence_id, request_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Deletion request not found") from exc
        except EvidenceGovernanceViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "evidence.deletion_decided",
            {"evidence_id": evidence_id, "request_id": request_id, "decision": request.decision},
        )
        return result

    @protected_router.get(
        "/evidence/{evidence_id}/privacy-summary",
        response_model=EvidencePrivacySummary,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def evidence_privacy_summary(evidence_id: str) -> EvidencePrivacySummary:
        try:
            return privacy_summary(evidence_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Evidence not found") from exc

    @protected_router.post(
        "/pcap/analyses",
        response_model=PcapAnalysisResponse,
        status_code=201,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    async def pcap_analysis_create(
        file: UploadFile = File(...),  # noqa: B008
        campaign_id: str | None = Form(default=None),
    ) -> PcapAnalysisResponse:
        tenant_id = get_principal().tenant_id
        file_name = Path(file.filename or "").name
        if not file_name or file_name != (file.filename or "") or len(file_name) > 255:
            raise HTTPException(status_code=400, detail="file name must be a single safe path component")
        if not file_name.lower().endswith((".pcap", ".pcapng")):
            raise HTTPException(status_code=415, detail="only .pcap and .pcapng evidence is accepted")
        data = await file.read(settings.pcap_max_upload_bytes + 1)
        if len(data) > settings.pcap_max_upload_bytes:
            raise HTTPException(status_code=413, detail="PCAP evidence exceeds the configured upload limit")
        try:
            result = register_pcap_analysis(
                data,
                file_name,
                tenant_id,
                campaign_id,
                session_factory,
                max_packets=settings.pcap_max_packets,
                max_endpoints=settings.pcap_max_endpoints,
                max_dns_queries=settings.pcap_max_dns_queries,
                max_flows=settings.pcap_max_flows,
                max_observations=settings.pcap_max_observations,
                redaction_salt=settings.pcap_redaction_salt,
                retention_days=settings.pcap_retention_days,
            )
        except PcapFormatError as exc:
            failure_code, safe_error = safe_parse_failure(exc)
            quarantine = quarantine_pcap(
                data,
                file_name,
                tenant_id,
                session_factory,
                failure_code=failure_code,
                parse_error=safe_error,
                retention_days=settings.pcap_quarantine_retention_days,
            )
            record_audit(
                "pcap.quarantined",
                {
                    "tenant_id": tenant_id,
                    "evidence_id": quarantine.evidence_id,
                    "failure_code": failure_code,
                },
            )
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Offline PCAP parsing failed; evidence was quarantined.",
                    "evidence_id": quarantine.evidence_id,
                    "failure_code": failure_code,
                },
            ) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
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

    @protected_router.get(
        "/pcap/analyses",
        response_model=list[PcapAnalysisSummary],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_analyses(limit: int = 20) -> list[PcapAnalysisSummary]:
        return list_pcap_analyses(get_principal().tenant_id, session_factory, limit)

    @protected_router.get(
        "/pcap/analyses/{analysis_id}/drilldown",
        response_model=PcapDrilldownResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_analysis_drilldown(analysis_id: str) -> PcapDrilldownResponse:
        try:
            return get_pcap_drilldown(
                analysis_id,
                get_principal().tenant_id,
                session_factory,
                max_flows=settings.pcap_drilldown_max_flows,
                max_dns=settings.pcap_drilldown_max_dns,
                max_observations=settings.pcap_drilldown_max_observations,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="PCAP analysis not found") from exc
        except PcapLifecycleViolation as exc:
            raise HTTPException(
                status_code=409,
                detail="PCAP evidence failed integrity or privacy verification",
            ) from exc

    @protected_router.get(
        "/pcap/analyses/{analysis_id}",
        response_model=PcapAnalysisResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_analysis_detail(analysis_id: str) -> PcapAnalysisResponse:
        try:
            return get_pcap_analysis(analysis_id, get_principal().tenant_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @protected_router.get(
        "/pcap/lifecycle",
        response_model=list[PcapLifecycleResponse],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_lifecycle_list(
        state: str | None = Query(default=None, min_length=1, max_length=32),
        limit: int = Query(default=20, ge=1, le=100),
    ) -> list[PcapLifecycleResponse]:
        try:
            return list_pcap_lifecycles(get_principal().tenant_id, session_factory, state=state, limit=limit)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid PCAP lifecycle filter") from exc

    @protected_router.get(
        "/pcap/evidence/{evidence_id}/lifecycle",
        response_model=PcapLifecycleResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_lifecycle(evidence_id: str) -> PcapLifecycleResponse:
        try:
            return get_pcap_lifecycle(evidence_id, get_principal().tenant_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="PCAP lifecycle not found") from exc

    @protected_router.get(
        "/pcap/evidence/{evidence_id}/manifest",
        response_model=PcapManifestVerification,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_manifest(evidence_id: str) -> PcapManifestVerification:
        try:
            return get_pcap_manifest(evidence_id, get_principal().tenant_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="PCAP manifest not found") from exc

    @protected_router.get(
        "/pcap/evidence/{evidence_id}/deletion-check",
        response_model=PcapDeletionCheckResponse,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def pcap_deletion_check(evidence_id: str) -> PcapDeletionCheckResponse:
        try:
            return check_pcap_deletion(evidence_id, get_principal().tenant_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="PCAP lifecycle not found") from exc

    @protected_router.get(
        "/evidence/{evidence_id}/pcap",
        response_model=PcapEvidenceView,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def evidence_pcap_view(evidence_id: str) -> PcapEvidenceView:
        try:
            return get_pcap_evidence_view_by_evidence(evidence_id, get_principal().tenant_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="PCAP evidence not found") from exc

    @protected_router.get(
        "/remediations",
        response_model=list[RemediationResponse],
        dependencies=[Depends(permission_dependency("read"))],
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
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "remediation.lifecycle_updated",
            {"remediation_id": remediation_id, "status": result.status, "actor": current_actor()},
        )
        return result

    @protected_router.patch(
        "/remediations/{remediation_id}/assignment",
        response_model=RemediationResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def remediation_assignment(
        remediation_id: str, request: RemediationAssignmentUpdate
    ) -> RemediationResponse:
        try:
            result = assign_remediation(remediation_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            "remediation.assigned",
            {"remediation_id": remediation_id, "assigned_to": result.assigned_to},
        )
        return result

    @protected_router.patch(
        "/remediations/{remediation_id}/verification",
        response_model=RemediationResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def remediation_verification(
        remediation_id: str, request: RemediationVerificationUpdate
    ) -> RemediationResponse:
        try:
            result = verify_remediation(remediation_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "remediation.verified",
            {"remediation_id": remediation_id, "status": result.verification_status},
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
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "risk.accepted",
            {"acceptance_id": result.acceptance_id, "approver": result.approver, "expires_on": result.expires_on},
        )
        return result

    @protected_router.patch(
        "/risk-acceptances/{acceptance_id}/decision",
        response_model=RiskAcceptanceResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def risk_acceptance_decision(
        acceptance_id: str, request: RiskAcceptanceDecisionRequest
    ) -> RiskAcceptanceResponse:
        try:
            result = decide_risk_acceptance(acceptance_id, request, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "risk.acceptance_decision",
            {"acceptance_id": acceptance_id, "decision": request.decision, "status": result.status},
        )
        return result

    @protected_router.post(
        "/risk-acceptances/{acceptance_id}/expire",
        response_model=RiskAcceptanceResponse,
        dependencies=[Depends(permission_dependency("manage_cases"))],
    )
    def risk_acceptance_expire(acceptance_id: str) -> RiskAcceptanceResponse:
        try:
            result = expire_risk_acceptance(acceptance_id, session_factory)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            "risk.acceptance_expired",
            {"acceptance_id": acceptance_id, "expires_on": result.expires_on},
        )
        return result

    @protected_router.get(
        "/scorecards/coverage",
        response_model=CoverageScorecard, dependencies=[Depends(permission_dependency("read"))]
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
        "/remediations/escalations",
        response_model=list[RemediationSlaEscalation],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def remediation_escalations_route() -> list[RemediationSlaEscalation]:
        return remediation_escalations(session_factory)

    @protected_router.get(
        "/trends/risk",
        response_model=list[TrendPoint], dependencies=[Depends(permission_dependency("read"))]
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
        "/discovery/jobs", response_model=DiscoveryJobStatus, status_code=202,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def discovery_job_create(request: DiscoveryJobCreate) -> DiscoveryJobStatus:
        principal = get_principal()
        requested_targets = [str(target) for target in request.targets]
        effective_dry_run = settings.dry_run or request.dry_run
        try:
            return discovery_jobs.submit(
                principal.tenant_id,
                requested_targets,
                request.profile,
                effective_dry_run,
                actor=current_actor(),
            )
        except DiscoveryRateLimitExceeded as exc:
            record_audit(
                "discovery.job_rate_limited",
                {"tenant_id": principal.tenant_id, "target_count": len(requested_targets)},
            )
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except ScopeViolation as exc:
            record_audit(
                "discovery.job_rejected",
                {"tenant_id": principal.tenant_id, "targets": requested_targets, "reason": str(exc)},
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @protected_router.get(
        "/discovery/jobs",
        response_model=list[DiscoveryJobStatus],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def discovery_job_list(limit: int = 20) -> list[DiscoveryJobStatus]:
        return discovery_jobs.list(get_principal().tenant_id, limit, actor=current_actor())

    @protected_router.get(
        "/discovery/jobs/{job_id}",
        response_model=DiscoveryJobStatus,
        dependencies=[Depends(permission_dependency("read"))],
    )
    def discovery_job_get(job_id: str) -> DiscoveryJobStatus:
        try:
            return discovery_jobs.get(get_principal().tenant_id, job_id, actor=current_actor())
        except DiscoveryJobNotFound as exc:
            raise HTTPException(status_code=404, detail="Discovery job not found") from exc

    @protected_router.get(
        "/inventory/assets/page",
        response_model=Page[InventoryAsset],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def inventory_assets_page(
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = Query(default=None, min_length=1, max_length=6, pattern=r"^\d{1,6}$"),
        query: str | None = Query(default=None, max_length=128),
        service: str | None = Query(default=None, max_length=64),
        port: int | None = Query(default=None, ge=1, le=65535),
    ) -> Page[InventoryAsset]:
        try:
            return discovery_jobs.inventory_page(
                get_principal().tenant_id,
                limit=limit,
                cursor=cursor,
                query=query,
                service=service,
                port=port,
                actor=current_actor(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @protected_router.get(
        "/inventory/assets",
        response_model=list[InventoryAsset],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def inventory_assets(limit: int = 100) -> list[InventoryAsset]:
        return discovery_jobs.inventory(get_principal().tenant_id, limit, actor=current_actor())

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

    @protected_router.get(
        "/detections/rules",
        response_model=list[DetectionRule],
        dependencies=[Depends(permission_dependency("read"))],
    )
    def detection_rules() -> list[DetectionRule]:
        return detection_catalog.list_rules()

    @protected_router.post(
        "/detections/rules",
        response_model=DetectionRule,
        status_code=201,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def detection_rule_create(request: DetectionRuleCreate) -> DetectionRule:
        try:
            result = detection_catalog.add_rule(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record_audit(
            "detection.rule_registered",
            {
                "rule_id": result.rule_id,
                "deployment_status": result.deployment_status,
                "requires_approval": result.requires_approval,
            },
        )
        return result

    @protected_router.post(
        "/detections/evaluate",
        response_model=DetectionEvaluationResponse,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def detection_evaluate(request: DetectionEvaluationRequest) -> DetectionEvaluationResponse:
        try:
            result = detection_catalog.evaluate(request.events, request.rule_ids)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            "detection.rules_evaluated",
            {
                "event_count": result.event_count,
                "rule_count": result.rule_count,
                "match_count": len(result.matches),
            },
        )
        return result

    @protected_router.post(
        "/detections/regressions/run",
        response_model=RegressionReport,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def detection_regressions(request: RegressionRunRequest) -> RegressionReport:
        try:
            result = detection_catalog.run_regressions(request.fixtures, request.rule_ids)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            "detection.regression_completed",
            {
                "run_id": result.run_id,
                "status": result.status,
                "total_cases": result.total_cases,
                "false_positive_rate": result.false_positive_rate,
            },
        )
        return result

    @protected_router.post(
        "/detections/lifecycle/gate",
        response_model=DetectionLifecycleGateResponse,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def detection_lifecycle_gate(request: DetectionLifecycleGateRequest) -> DetectionLifecycleGateResponse:
        principal = get_principal()
        try:
            result = detection_lifecycle.run_gate(
                request.pack,
                request.fixtures,
                tenant_id=principal.tenant_id,
                actor=principal.username,
                rule_ids=request.rule_ids,
                dry_run=settings.dry_run or request.dry_run,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        audit.record(
            "detection.lifecycle_gate_completed",
            {
                "gate_id": result.gate_id,
                "pack_id": result.pack_id,
                "pack_version": result.pack_version,
                "status": result.status,
                "rule_count": len(result.validation),
                "error_count": len(result.errors),
                "dry_run": result.dry_run,
            },
            actor=principal.username,
        )
        return result

    @protected_router.post(
        "/detections/coverage",
        response_model=DetectionCoverageReport,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def detection_coverage(request: DetectionCoverageRequest) -> DetectionCoverageReport:
        principal = get_principal()
        if any(event.tenant_id != principal.tenant_id for event in request.telemetry):
            raise HTTPException(status_code=403, detail="Telemetry tenant does not match authenticated tenant")
        if any(path.tenant_id != principal.tenant_id for path in request.attack_paths):
            raise HTTPException(status_code=403, detail="Attack-path tenant does not match authenticated tenant")
        try:
            result = detection_catalog.coverage_report(
                request.telemetry,
                request.rule_ids,
                tenant_id=principal.tenant_id,
                actor=principal.username,
                attack_paths=request.attack_paths,
                dry_run=settings.dry_run or request.dry_run,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record_audit(
            "detection.coverage_calculated",
            {
                "run_id": result.run_id,
                "tenant_id": result.tenant_id,
                "expected_rule_count": result.expected_rule_count,
                "detected_rule_count": result.detected_rule_count,
                "path_count": result.path_count,
                "covered_path_count": result.covered_path_count,
                "dry_run": result.dry_run,
            },
            actor=principal.username,
        )
        return result

    @protected_router.post(
        "/detections/regressions/normalized",
        response_model=NormalizedRegressionReport,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def detection_normalized_regressions(request: NormalizedRegressionRequest) -> NormalizedRegressionReport:
        principal = get_principal()
        if any(
            event.tenant_id != principal.tenant_id
            for fixture in request.fixtures
            for event in fixture.telemetry
        ):
            raise HTTPException(
                status_code=403, detail="Regression telemetry tenant does not match authenticated tenant"
            )
        if any(
            path.tenant_id != principal.tenant_id
            for fixture in request.fixtures
            for path in fixture.attack_paths
        ):
            raise HTTPException(
                status_code=403, detail="Regression attack-path tenant does not match authenticated tenant"
            )
        try:
            result = detection_catalog.run_normalized_regressions(
                request.fixtures,
                request.rule_ids,
                tenant_id=principal.tenant_id,
                actor=principal.username,
                dry_run=settings.dry_run or request.dry_run,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record_audit(
            "detection.normalized_regression_completed",
            {
                "run_id": result.run_id,
                "tenant_id": result.tenant_id,
                "total_cases": result.total_cases,
                "failed_cases": result.failed_cases,
                "false_positive_rate": result.false_positive_rate,
                "dry_run": result.dry_run,
            },
            actor=principal.username,
        )
        return result

    @protected_router.post(
        "/detections/ad",
        response_model=list[FindingInput],
        dependencies=[Depends(permission_dependency("analyze"))],
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
        "/attack-paths/analyze",
        response_model=AttackPathAnalysisResponse,
        dependencies=[Depends(permission_dependency("analyze"))],
    )
    def attack_paths_analyze(request: AttackPathAnalysisRequest) -> AttackPathAnalysisResponse:
        principal = get_principal()
        if request.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=403, detail="Attack-path tenant does not match authenticated tenant")
        with session_factory() as session:
            authorized_asset_ids = {
                asset_id
                for (asset_id,) in session.query(Asset.id).filter(Asset.tenant_id == principal.tenant_id).all()
            }
            authorized_evidence_ids = {
                evidence_id
                for (evidence_id,) in session.query(EvidenceItem.id)
                .filter(EvidenceItem.tenant_id == principal.tenant_id)
                .all()
            }
        try:
            result = analyze_attack_path_risk(
                request,
                authorized_asset_ids=authorized_asset_ids,
                authorized_evidence_ids=authorized_evidence_ids,
            )
            persistence_record = to_persistence_record(result, actor_id=principal.user_id)
            register_attack_path_analysis(
                result,
                tenant_id=principal.tenant_id,
                actor_id=principal.user_id,
                session_factory=session_factory,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record_audit(
            "attack_paths.analyzed",
            {
                "tenant_id": request.tenant_id,
                "analysis_id": persistence_record.analysis_id,
                "graph_fingerprint": persistence_record.graph_fingerprint,
                "node_count": result.graph_summary.node_count,
                "edge_count": result.graph_summary.edge_count,
                "path_count": result.graph_summary.viable_path_count,
                "critical_path_count": result.graph_summary.critical_path_count,
                "asset_count": len(result.asset_ids),
                "evidence_count": len(result.evidence_ids),
                "remediation_link_count": len(result.remediation_links),
            },
        )
        return result

    @protected_router.post(
        "/copilot/explain",
        response_model=CopilotExplanationResponse,
        dependencies=[
            Depends(permission_dependency("analyze")),
            Depends(rate_limit_dependency(copilot_limiter)),
        ],
    )
    def copilot_explain(request: CopilotExplainRequest) -> CopilotExplanationResponse:
        result = assess_with_copilot(request)
        record_audit(
            "copilot.explanation_generated",
            {
                "subject_type": result.subject_type,
                "deterministic_tier": result.deterministic_tier,
                "tier": result.tier,
                "ai_status": result.ai_status,
                "fallback_reason": result.fallback_reason,
                "context_sha256": result.context_sha256,
                "data_egress": result.data_egress,
                "cache_hit": result.cache_hit,
            },
        )
        return result

    @protected_router.post(
        "/risk/ai-assess",
        response_model=CopilotExplanationResponse,
        dependencies=[
            Depends(permission_dependency("analyze")),
            Depends(rate_limit_dependency(copilot_limiter)),
        ],
    )
    def risk_ai_assess(request: CopilotExplainRequest) -> CopilotExplanationResponse:
        result = assess_with_copilot(request)
        record_audit(
            "risk.ai_assessed",
            {
                "subject_type": result.subject_type,
                "deterministic_tier": result.deterministic_tier,
                "tier": result.tier,
                "ai_status": result.ai_status,
                "fallback_reason": result.fallback_reason,
                "context_sha256": result.context_sha256,
                "data_egress": result.data_egress,
                "cache_hit": result.cache_hit,
            },
        )
        return result

    @protected_router.post(
        "/purple/analyze",
        response_model=DetectionGapReport,
        dependencies=[Depends(permission_dependency("analyze"))],
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
