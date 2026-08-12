from __future__ import annotations

import networkx as nx

from app.schemas.contracts import AttackEdge, AttackPath, GraphRequest, GraphResult


def analyze_attack_graph(request: GraphRequest) -> GraphResult:
    graph = nx.DiGraph()
    for node in request.nodes:
        graph.add_node(node.id, **node.model_dump())
    for edge in request.edges:
        graph.add_edge(edge.source, edge.target, weight=edge.weight, payload=edge.model_dump())

    if request.source_node not in graph:
        raise ValueError(f"Source node is absent from graph: {request.source_node}")
    if request.target_node not in graph:
        raise ValueError(f"Target node is absent from graph: {request.target_node}")

    paths: list[AttackPath] = []
    try:
        node_path = nx.dijkstra_path(graph, request.source_node, request.target_node, weight="weight")
        edge_payloads = [graph.edges[source, target]["payload"] for source, target in zip(node_path, node_path[1:])]
        paths.append(
            AttackPath(
                nodes=node_path,
                edges=[AttackEdge(**payload) for payload in edge_payloads],
                total_weight=float(nx.path_weight(graph, node_path, weight="weight")),
            )
        )
    except nx.NetworkXNoPath:
        pass

    centrality = nx.betweenness_centrality(graph, normalized=True, weight="weight")
    chokepoints = [
        {
            "node_id": node_id,
            "label": graph.nodes[node_id].get("label", node_id),
            "centrality": round(score, 4),
            "kind": graph.nodes[node_id].get("kind", "unknown"),
        }
        for node_id, score in sorted(centrality.items(), key=lambda item: item[1], reverse=True)
        if score > 0
    ]
    return GraphResult(paths=paths, chokepoints=chokepoints)
