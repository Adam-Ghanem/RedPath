from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.core.audit import AuditLogger
from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeViolation
from app.db.models import create_session_factory
from app.plugins.registry import list_plugins
from app.schemas.contracts import (
    AssessmentRunSummary,
    CorrelatedRisk,
    CorrelationRequest,
    DetectionGapReport,
    FindingInput,
    GraphRequest,
    GraphResult,
    PurpleAnalysisRequest,
    ReconRequest,
    ReconResult,
    ScenarioRunRequest,
    ScenarioRunResponse,
    ScenarioSpec,
)
from app.services.ad_detection import detect_ad_findings
from app.services.correlation import correlate_findings
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
