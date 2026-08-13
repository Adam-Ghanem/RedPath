from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from typing import Iterable

import networkx as nx

from app.schemas.contracts import (
    AttackEdge,
    AttackNode,
    AttackPathAnalysisRequest,
    AttackPathAnalysisResponse,
    ChokePoint,
    GraphSummary,
    RankedAttackPath,
    RiskExplanation,
    RiskFactor,
)

LIKELIHOOD_WEIGHT = 0.4
IMPACT_WEIGHT = 0.4
STEALTH_WEIGHT = 0.2


def _round(value: float) -> float:
    return round(value, 4)


def _path_id(nodes: Iterable[str]) -> str:
    canonical = "->".join(nodes)
    return f"path-{sha256(canonical.encode("utf-8")).hexdigest()[:12]}"


def _risk_level(score: float) -> str:
    if score >= 7.0:
        return "critical"
    if score >= 5.0:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"


def _effective_ids(request: AttackPathAnalysisRequest) -> tuple[list[str], list[str]]:
    node_by_id = {node.id: node for node in request.nodes}
    entries = request.entry_point_ids or [node.id for node in request.nodes if node.is_entry_point]
    crowns = request.crown_jewel_ids or [node.id for node in request.nodes if node.is_crown_jewel]
    if not entries:
        raise ValueError("At least one entry point is required via entry_point_ids or is_entry_point")
    if not crowns:
        raise ValueError("At least one crown jewel is required via crown_jewel_ids or is_crown_jewel")
    unknown_entries = sorted(set(entries) - node_by_id.keys())
    unknown_crowns = sorted(set(crowns) - node_by_id.keys())
    if unknown_entries or unknown_crowns:
        raise ValueError(
            f"Unknown graph endpoints: entries={unknown_entries or 'none'}, crowns={unknown_crowns or 'none'}"
        )
    return sorted(set(entries)), sorted(set(crowns))


def _build_graph(request: AttackPathAnalysisRequest) -> tuple[nx.DiGraph, list[str]]:
    graph = nx.DiGraph()
    node_ids = {node.id for node in request.nodes}
    for node in request.nodes:
        graph.add_node(node.id, payload=node)

    warnings: list[str] = []
    for edge in request.edges:
        if edge.source not in node_ids or edge.target not in node_ids:
            raise ValueError(f"Edge references unknown node: {edge.source}->{edge.target}")
        if graph.has_edge(edge.source, edge.target):
            warnings.append(f"Duplicate edge {edge.source}->{edge.target}; retained the first edge")
            continue
        graph.add_edge(edge.source, edge.target, payload=edge)
    return graph, warnings


def _edge_for_path(graph: nx.DiGraph, nodes: list[str]) -> list[AttackEdge]:
    return [graph.edges[source, target]["payload"] for source, target in zip(nodes, nodes[1:])]


def _aggregate_category(edges: list[AttackEdge]) -> str:
    categories = Counter(edge.category for edge in edges)
    return sorted(categories, key=lambda category: (-categories[category], category))[0]


def _explain_path(
    nodes: list[str],
    edges: list[AttackEdge],
    node_by_id: dict[str, AttackNode],
) -> RankedAttackPath:
    likelihood = min(edge.likelihood for edge in edges)
    impact = max(max(edge.impact for edge in edges), node_by_id[nodes[-1]].criticality * 10)
    stealth = min(edge.stealth for edge in edges)
    composite = (likelihood * LIKELIHOOD_WEIGHT) + (impact * IMPACT_WEIGHT) + (stealth * STEALTH_WEIGHT)
    risk_score = composite * 10
    technique_values: set[str] = set()
    for edge in edges:
        if edge.technique_id:
            technique_values.add(edge.technique_id)
        technique_values.update(edge.mitre_techniques)
    techniques = sorted(technique_values)
    prerequisites = sorted({item for edge in edges for item in edge.prerequisites})
    zones = {node_by_id[node].zone for node in nodes}
    hybrid = any(edge.hybrid for edge in edges) or ("on_prem" in zones and "cloud" in zones)
    path_id = _path_id(nodes)
    factors = [
        RiskFactor(
            dimension="likelihood",
            score=_round(likelihood),
            weight=LIKELIHOOD_WEIGHT,
            weighted_contribution=_round(likelihood * LIKELIHOOD_WEIGHT),
            evidence=[f"Minimum edge prerequisite-availability score across {len(edges)} hop(s)"],
        ),
        RiskFactor(
            dimension="impact",
            score=_round(impact),
            weight=IMPACT_WEIGHT,
            weighted_contribution=_round(impact * IMPACT_WEIGHT),
            evidence=[f"Maximum edge impact and terminal criticality for {node_by_id[nodes[-1]].label}"],
        ),
        RiskFactor(
            dimension="stealth",
            score=_round(stealth),
            weight=STEALTH_WEIGHT,
            weighted_contribution=_round(stealth * STEALTH_WEIGHT),
            evidence=["Minimum inverted-detection score across the path edges"],
        ),
    ]
    mitigation = sorted({edge.hardening_action for edge in edges})
    assumptions = [
        (
            "Scores are supplied by authorized defensive telemetry or asset context; the engine "
            "does not probe or execute against targets."
        ),
        "A path is considered viable when all supplied graph edges and their recorded prerequisites are present.",
    ]
    if hybrid:
        assumptions.append("The path crosses an on-premises/cloud boundary or is explicitly marked hybrid.")
    summary = (
        f"{path_id} ranks {_risk_level(composite)} at {risk_score:.1f}/100 because "
        f"likelihood={likelihood:.1f}, impact={impact:.1f}, and stealth={stealth:.1f} "
        f"produce a weighted composite of {composite:.2f}/10."
    )
    return RankedAttackPath(
        path_id=path_id,
        hops=nodes,
        edges=edges,
        category=_aggregate_category(edges),
        composite_score=_round(composite),
        risk_score=_round(risk_score),
        risk_level=_risk_level(composite),
        likelihood=_round(likelihood),
        impact=_round(impact),
        stealth=_round(stealth),
        mitre_techniques=techniques,
        prerequisites=prerequisites,
        is_hybrid=hybrid,
        explanation=RiskExplanation(summary=summary, factors=factors, assumptions=assumptions, mitigation=mitigation),
    )


def _choke_points(
    graph: nx.DiGraph,
    paths: list[RankedAttackPath],
    threshold: float,
) -> list[ChokePoint]:
    path_ids_by_node: dict[str, set[str]] = defaultdict(set)
    path_by_id = {path.path_id: path for path in paths}
    for path in paths:
        if path.composite_score < threshold:
            continue
        for node_id in path.hops[1:-1]:
            path_ids_by_node[node_id].add(path.path_id)

    result: list[ChokePoint] = []
    for node_id, path_ids in path_ids_by_node.items():
        ordered_path_ids = sorted(path_ids)
        count = len(ordered_path_ids)
        priority = "P0" if count >= 5 else "P1" if count >= 3 else "P2"
        contributing_edges = [
            edge
            for path_id in ordered_path_ids
            for edge in path_by_id[path_id].edges
            if edge.source == node_id or edge.target == node_id
        ]
        action = sorted({edge.hardening_action for edge in contributing_edges})[0]
        effort = min(edge.estimated_effort_hours for edge in contributing_edges)
        result.append(
            ChokePoint(
                node_id=node_id,
                label=graph.nodes[node_id]["payload"].label,
                paths_blocked=count,
                path_ids=ordered_path_ids,
                priority_class=priority,
                hardening_action=action,
                estimated_effort_hours=effort,
                rationale=(
                    f"Hardening this node addresses {count} path(s) at or above the "
                    f"{threshold:.1f}/10 critical threshold."
                ),
            )
        )
    return sorted(result, key=lambda item: (-item.paths_blocked, item.priority_class, item.node_id))


def analyze_attack_path_risk(request: AttackPathAnalysisRequest) -> AttackPathAnalysisResponse:
    """Analyze only caller-supplied graph data; no network or credential operation is performed."""
    node_by_id = {node.id: node for node in request.nodes}
    if len(node_by_id) != len(request.nodes):
        raise ValueError("Node IDs must be unique")
    entries, crowns = _effective_ids(request)
    graph, warnings = _build_graph(request)
    candidates: list[RankedAttackPath] = []
    truncated = False

    for entry in entries:
        for crown in crowns:
            if entry == crown:
                continue
            for nodes in nx.all_simple_paths(graph, entry, crown, cutoff=request.max_hops):
                candidates.append(_explain_path(list(nodes), _edge_for_path(graph, list(nodes)), node_by_id))
                if len(candidates) >= request.max_paths:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break

    ranked = sorted(candidates, key=lambda path: (-path.composite_score, -path.impact, len(path.hops), path.path_id))
    ranked = ranked[: request.max_paths]
    reachable_crowns = {path.hops[-1] for path in ranked}
    unreachable = sorted(set(crowns) - reachable_crowns)
    hybrid_paths = [path.path_id for path in ranked if path.is_hybrid]
    critical_paths = [path for path in ranked if path.composite_score >= request.critical_threshold]
    if unreachable:
        warnings.append("Some crown jewels have no viable path from the supplied entry points")
    if truncated:
        warnings.append(f"Path enumeration capped at max_paths={request.max_paths}")

    return AttackPathAnalysisResponse(
        tenant_id=request.tenant_id,
        graph_summary=GraphSummary(
            node_count=len(request.nodes),
            edge_count=len(request.edges),
            entry_point_count=len(entries),
            crown_jewel_count=len(crowns),
            viable_path_count=len(ranked),
            critical_path_count=len(critical_paths),
            hybrid_path_count=len(hybrid_paths),
            truncated=truncated,
        ),
        entry_points=entries,
        crown_jewel_nodes=crowns,
        ranked_paths=ranked,
        choke_points=_choke_points(graph, ranked, request.critical_threshold),
        cloud_paths=hybrid_paths,
        unreachable_crown_jewels=unreachable,
        warnings=warnings,
    )
