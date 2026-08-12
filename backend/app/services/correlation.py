from __future__ import annotations

from app.schemas.contracts import CorrelatedRisk, FindingInput, GraphResult

_SEVERITY_BASE = {
    "info": 12.0,
    "low": 28.0,
    "medium": 48.0,
    "high": 70.0,
    "critical": 88.0,
}


def correlate_findings(findings: list[FindingInput], graph: GraphResult | None = None) -> list[CorrelatedRisk]:
    centrality_by_label = {
        str(item.get("label")): float(item.get("centrality", 0.0))
        for item in (graph.chokepoints if graph else [])
    }
    graph_techniques = {
        edge.technique_id
        for path in (graph.paths if graph else [])
        for edge in path.edges
        if edge.technique_id
    }
    results: list[CorrelatedRisk] = []
    for finding in findings:
        path_relevance = centrality_by_label.get(finding.asset_id or "", 0.0)
        cvss_component = (finding.cvss_score or 0.0) * 5.0
        severity_component = _SEVERITY_BASE[finding.severity]
        path_component = path_relevance * 20.0
        risk_score = min(100.0, round(max(severity_component, cvss_component) + path_component, 2))
        related = sorted(graph_techniques)
        rationale = (
            f"Base severity contributes {max(severity_component, cvss_component):.2f}; "
            f"path centrality contributes {path_component:.2f}."
        )
        if finding.technique_id and finding.technique_id in graph_techniques:
            rationale += f" {finding.technique_id} is present on the modeled attack path."
        results.append(
            CorrelatedRisk(
                finding_title=finding.title,
                technique_id=finding.technique_id,
                asset_id=finding.asset_id,
                risk_score=risk_score,
                path_relevance=round(path_relevance, 4),
                related_techniques=related,
                rationale=rationale,
            )
        )
    return sorted(results, key=lambda item: item.risk_score, reverse=True)
