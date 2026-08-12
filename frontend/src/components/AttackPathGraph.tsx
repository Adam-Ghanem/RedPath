import { ChevronRight, GitBranch, Network, ShieldAlert, Target } from "lucide-react";
import { attackPaths, graphEdges, graphNodes, pathById, type Severity } from "../data/redpathDemo";

const severityColor: Record<Severity, string> = {
  Critical: "#ff6d7a",
  High: "#ffbd62",
  Medium: "#e8d26e",
  Low: "#66e3a5",
};

type AttackPathGraphProps = {
  selectedPathId: string;
  selectedAssetId: string;
  onSelectPath: (pathId: string) => void;
  onSelectAsset: (assetId: string) => void;
};

export default function AttackPathGraph({ selectedPathId, selectedAssetId, onSelectPath, onSelectAsset }: AttackPathGraphProps) {
  const activePath = pathById(selectedPathId);
  const activeEdges = new Set(activePath.edgeIds);
  const activeNodes = new Set(activePath.nodeIds);

  return (
    <div className="graph-shell">
      <div className="graph-canvas" aria-label="Interactive synthetic Active Directory attack path graph">
        <div className="graph-topline">
          <div className="eyebrow"><Network size={14} /> Synthetic lab topology</div>
          <div className="graph-legend" aria-label="Graph legend">
            <span><i className="legend-dot critical" /> Critical path</span>
            <span><i className="legend-dot chokepoint" /> Chokepoint</span>
            <span><i className="legend-line" /> Weighted trust edge</span>
          </div>
        </div>
        <svg viewBox="0 0 100 100" role="img" aria-labelledby="graph-title graph-description" preserveAspectRatio="xMidYMid meet">
          <title id="graph-title">RedPath synthetic Active Directory attack path graph</title>
          <desc id="graph-description">Select nodes and paths to inspect weighted relationships and chokepoints.</desc>
          <defs>
            <filter id="nodeGlow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="1.5" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>
          {graphEdges.map((edge) => {
            const source = graphNodes.find((node) => node.id === edge.source)!;
            const target = graphNodes.find((node) => node.id === edge.target)!;
            const isActive = activeEdges.has(edge.id);
            return (
              <g className="graph-edge-group" key={edge.id}>
                <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} className={isActive ? "graph-edge active" : "graph-edge"} />
                <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 2} className={isActive ? "edge-label active" : "edge-label"}>{edge.weight}</text>
              </g>
            );
          })}
          {graphNodes.map((node) => {
            const isActive = activeNodes.has(node.id);
            const isSelected = selectedAssetId === node.id;
            const isChokepoint = node.status === "chokepoint";
            return (
              <g
                className={`graph-node ${isActive ? "active" : ""} ${isSelected ? "selected" : ""} ${isChokepoint ? "is-chokepoint" : ""}`}
                key={node.id}
                onClick={() => onSelectAsset(node.id)}
                onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onSelectAsset(node.id); }}
                role="button"
                tabIndex={0}
                aria-label={`${node.label}: ${node.subtitle}, ${node.severity} severity`}
              >
                <circle cx={node.x} cy={node.y} r={isSelected ? 5.4 : 4.3} className="node-ring" />
                <circle cx={node.x} cy={node.y} r={2.8} fill={severityColor[node.severity]} filter={isActive || isChokepoint ? "url(#nodeGlow)" : undefined} />
                <text x={node.x} y={node.y + 8} className="node-label">{node.label}</text>
                <text x={node.x} y={node.y + 11.6} className="node-subtitle">{node.subtitle}</text>
              </g>
            );
          })}
        </svg>
        <div className="graph-note"><ShieldAlert size={15} /> All paths are calculated from pre-seeded, synthetic lab observations. Nothing runs against a network.</div>
      </div>
      <aside className="path-inspector">
        <div className="inspector-heading"><span>Path explorer</span><GitBranch size={16} /></div>
        <div className="path-list">
          {attackPaths.map((path) => (
            <button className={`path-option ${path.id === selectedPathId ? "active" : ""}`} key={path.id} onClick={() => onSelectPath(path.id)}>
              <span className={`severity-square ${path.risk.toLowerCase()}`} />
              <span className="path-option-copy"><strong>{path.name}</strong><small>{path.cost} weighted hops · {path.risk}</small></span>
              <ChevronRight size={15} />
            </button>
          ))}
        </div>
        <div className="active-path-detail">
          <div className="detail-kicker"><Target size={14} /> Current shortest path</div>
          <h3>{activePath.name}</h3>
          <p>{activePath.summary}</p>
          <div className="detail-stat"><span>Chokepoint</span><strong>{activePath.chokepoint}</strong></div>
          <div className="path-route">{activePath.nodeIds.map((nodeId, index) => <span key={nodeId}>{index > 0 && <ChevronRight size={12} />} {nodeId}</span>)}</div>
        </div>
      </aside>
    </div>
  );
}
