from __future__ import annotations

from typing import Any, Callable

from app.db.models import AttackPathAnalysis, EvidenceItem, Finding
from app.schemas.contracts import (
    AttackPathAnalysisResponse,
    CopilotAttackPathSummary,
    CopilotDetectionEvidence,
    CopilotExplainRequest,
    CopilotResolvedContext,
)

SessionFactory = Callable[[], Any]


class CopilotSourceNotFound(Exception):
    """A requested source is absent or not visible in the authenticated tenant."""


_SEVERITY_SCORE = {"info": 10.0, "low": 25.0, "medium": 50.0, "high": 75.0, "critical": 95.0}


def _tier(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _evidence_ids_from_finding(finding: Finding) -> list[str]:
    raw = finding.evidence if isinstance(finding.evidence, dict) else {}
    values = raw.get("evidence_ids", [])
    if not isinstance(values, list):
        return []
    return [str(value)[:128] for value in values[:8] if isinstance(value, str) and value]


def _evidence_rows(
    session: Any,
    *,
    tenant_id: str,
    requested_ids: list[str],
    technique_id: str | None,
) -> list[EvidenceItem]:
    query = session.query(EvidenceItem).filter(EvidenceItem.tenant_id == tenant_id)
    if requested_ids:
        query = query.filter(EvidenceItem.id.in_(requested_ids))
    elif technique_id:
        query = query.filter(EvidenceItem.technique_id == technique_id)
    return query.order_by(EvidenceItem.created_at.desc()).limit(8).all()


def _evidence_context(
    rows: list[EvidenceItem],
    *,
    fallback_id: str,
    fallback_signal: str,
    severity: str,
    technique_id: str | None,
) -> list[CopilotDetectionEvidence]:
    if not rows:
        return [
            CopilotDetectionEvidence(
                evidence_id=fallback_id,
                severity=severity,
                technique_id=technique_id,
                signal=fallback_signal[:512],
            )
        ]
    return [
        CopilotDetectionEvidence(
            evidence_id=row.id,
            severity=severity,
            technique_id=row.technique_id or technique_id,
            signal=f"{row.evidence_type} {row.title}"[:512],
        )
        for row in rows
    ]


def resolve_copilot_source(
    request: CopilotExplainRequest,
    *,
    tenant_id: str,
    session_factory: SessionFactory,
) -> CopilotResolvedContext:
    """Resolve only tenant-visible server records; client scores and context are never read."""
    with session_factory() as session:
        if request.source_type == "finding":
            finding = (
                session.query(Finding)
                .filter(Finding.id == request.finding_id, Finding.tenant_id == tenant_id)
                .one_or_none()
            )
            if finding is None:
                raise CopilotSourceNotFound("finding not found")
            evidence_ids = _evidence_ids_from_finding(finding)
            rows = _evidence_rows(
                session,
                tenant_id=tenant_id,
                requested_ids=evidence_ids,
                technique_id=finding.technique_id,
            )
            score = max(
                _SEVERITY_SCORE.get(finding.severity, 10.0),
                (finding.cvss_score or 0.0) * 10.0,
            )
            return CopilotResolvedContext(
                tenant_id=tenant_id,
                source_type="finding",
                source_id=finding.id,
                deterministic_score=min(100.0, score),
                centrality=0.5 if finding.asset_id else 0.0,
                deterministic_tier=_tier(score),
                evidence=_evidence_context(
                    rows,
                    fallback_id=f"finding:{finding.id}",
                    fallback_signal=finding.description,
                    severity=finding.severity,
                    technique_id=finding.technique_id,
                ),
            )

        analysis = (
            session.query(AttackPathAnalysis)
            .filter(AttackPathAnalysis.id == request.analysis_id, AttackPathAnalysis.tenant_id == tenant_id)
            .one_or_none()
        )
        if analysis is None:
            raise CopilotSourceNotFound("attack path analysis not found")
        paths = analysis.summary_json.get("paths", []) if isinstance(analysis.summary_json, dict) else []
        path = next((item for item in paths if item.get("path_id") == request.path_id), None)
        if not isinstance(path, dict):
            raise CopilotSourceNotFound("attack path not found")
        asset_ids = [value for value in path.get("asset_ids", []) if isinstance(value, str)][:50]
        evidence_ids = [value for value in path.get("evidence_ids", []) if isinstance(value, str)][:50]
        technique_ids = [value for value in path.get("technique_ids", []) if isinstance(value, str)][:32]
        rows = _evidence_rows(
            session,
            tenant_id=tenant_id,
            requested_ids=evidence_ids,
            technique_id=technique_ids[0] if technique_ids else None,
        )
        score = float(path.get("risk_score", 0.0))
        attack_path = CopilotAttackPathSummary(
            risk_score=max(0.0, min(100.0, score)),
            centrality=float(path.get("centrality", 0.0)),
            hop_count=int(path.get("hop_count", 0)),
            asset_count=len(asset_ids),
            evidence_count=len(evidence_ids),
            asset_ids=asset_ids,
            evidence_ids=evidence_ids,
            technique_ids=technique_ids,
            rationale=str(path.get("rationale", ""))[:512],
        )
        return CopilotResolvedContext(
            tenant_id=tenant_id,
            source_type="attack_path",
            source_id=str(path["path_id"]),
            deterministic_score=attack_path.risk_score,
            centrality=attack_path.centrality,
            deterministic_tier=_tier(score),
            attack_path=attack_path,
            evidence=_evidence_context(
                rows,
                fallback_id=f"path:{path['path_id']}",
                fallback_signal=attack_path.rationale,
                severity=(
                    "critical"
                    if score >= 80
                    else "high"
                    if score >= 60
                    else "medium"
                    if score >= 30
                    else "low"
                ),
                technique_id=technique_ids[0] if technique_ids else None,
            ),
        )


def register_attack_path_analysis(
    response: AttackPathAnalysisResponse,
    *,
    tenant_id: str,
    actor_id: str,
    session_factory: SessionFactory,
) -> None:
    """Register a minimized, tenant-bound path summary for later identifier-only assessment."""
    summary: dict[str, Any] = {
        "analysis_id": response.analysis_id,
        "graph_fingerprint": response.graph_fingerprint,
        "paths": [],
    }
    for path in response.ranked_paths:
        choke_count = sum(1 for choke in response.choke_points if path.path_id in choke.path_ids)
        summary["paths"].append(
            {
                "path_id": path.path_id,
                "risk_score": path.risk_score,
                "risk_level": path.risk_level,
                "centrality": min(1.0, choke_count / 5.0),
                "hop_count": len(path.hops) - 1,
                "asset_ids": path.asset_ids[:50],
                "evidence_ids": path.evidence_ids[:50],
                "technique_ids": path.mitre_techniques[:32],
                "rationale": path.explanation.remediation_rationale[:512],
            }
        )
    with session_factory() as session:
        existing = session.query(AttackPathAnalysis).filter(AttackPathAnalysis.id == response.analysis_id).one_or_none()
        if existing is not None and existing.tenant_id != tenant_id:
            raise PermissionError("analysis belongs to another tenant")
        if existing is None:
            session.add(
                AttackPathAnalysis(
                    id=response.analysis_id,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    graph_fingerprint=response.graph_fingerprint,
                    summary_json=summary,
                )
            )
        else:
            existing.summary_json = summary
            existing.actor_id = actor_id
        session.commit()
