import { useMemo, useState } from "react";
import type { GraphEdge, GraphNode } from "../data/mock";

type Props = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

export default function AttackPathGraph({ nodes, edges }: Props) {
  const [selected, setSelected] = useState(nodes[0]?.id ?? "");
  const byId = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selectedNode = byId.get(selected);

  return (
    <div className="graph-shell">
      <svg viewBox="0 0 760 340" role="img" aria-label="Interactive attack path graph" className="attack-graph">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#49d7e8" />
          </marker>
          <filter id="softGlow"><feGaussianBlur stdDeviation="4" result="coloredBlur" /><feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        </defs>
        <g className="edge-layer">
          {edges.map((edge) => {
            const source = byId.get(edge.source)!;
            const target = byId.get(edge.target)!;
            const highlighted = selected === edge.source || selected === edge.target;
            return (
              <g key={`${edge.source}-${edge.target}`} className={highlighted ? "edge-group active" : "edge-group"}>
                <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} markerEnd="url(#arrow)" />
                <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 9}>{edge.technique}</text>
              </g>
            );
          })}
        </g>
        <g className="node-layer">
          {nodes.map((node) => {
            const active = node.id === selected;
            return (
              <g key={node.id} className={`graph-node ${node.status} ${active ? "selected" : ""}`} onClick={() => setSelected(node.id)} tabIndex={0} role="button" aria-label={`Select ${node.label}`}>
                <circle cx={node.x} cy={node.y} r={active ? 31 : 27} filter={active ? "url(#softGlow)" : undefined} />
                <text x={node.x} y={node.y + 4} textAnchor="middle">{node.label}</text>
                <text className="node-kind" x={node.x} y={node.y + 48} textAnchor="middle">{node.kind}</text>
              </g>
            );
          })}
        </g>
      </svg>
      <div className="graph-detail">
        <div>
          <span className="eyebrow">Selected node</span>
          <strong>{selectedNode?.label ?? "—"}</strong>
        </div>
        <div className="detail-chip">{selectedNode?.status ?? "unknown"}</div>
      </div>
    </div>
  );
}
