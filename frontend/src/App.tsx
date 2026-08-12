import { useEffect, useState } from "react";
import AttackPathGraph from "./components/AttackPathGraph";
import { coverage, graphEdges, graphNodes } from "./data/mock";

const API_BASE = "/api/v1";

function MetricCard({ label, value, tone, note }: { label: string; value: string; tone: string; note: string }) {
  return (
    <article className="metric-card">
      <div className="metric-top"><span className="eyebrow">{label}</span><span className={`metric-dot ${tone}`} /></div>
      <strong>{value}</strong>
      <span className="metric-note">{note}</span>
    </article>
  );
}

function App() {
  const [apiOnline, setApiOnline] = useState(false);
  const [busy, setBusy] = useState(false);
  const [lastAction, setLastAction] = useState("No actions executed. Dry-run is enforced.");

  useEffect(() => {
    fetch(`${API_BASE}/health`).then((response) => setApiOnline(response.ok)).catch(() => setApiOnline(false));
  }, []);

  async function runDryRecon() {
    setBusy(true);
    setLastAction("Planning scoped recon commands…");
    try {
      const response = await fetch(`${API_BASE}/recon`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets: ["192.168.56.10"], profile: "service_inventory", dry_run: true }),
      });
      if (!response.ok) throw new Error("API unavailable");
      const result = await response.json();
      setLastAction(`${result.commands.length} commands planned; no network command executed.`);
    } catch {
      setLastAction("Demo mode: API not connected. No command was executed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><img className="brand-logo" src="/assets/redpath-logo.png" alt="RedPath logo" /><div><strong>REDPATH</strong><span>ATTACK PATH CONSOLE</span></div></div>
        <nav className="nav-stack" aria-label="Primary navigation">
          <a className="nav-item active" href="#overview"><span>◈</span>Overview</a>
          <a className="nav-item" href="#attack-graph"><span>⌁</span>Attack paths</a>
          <a className="nav-item" href="#coverage"><span>⊕</span>Detection coverage</a>
          <a className="nav-item" href="#findings"><span>◇</span>Findings</a>
          <a className="nav-item" href="#reports"><span>▤</span>Reports</a>
        </nav>
        <div className="sidebar-foot"><span className="status-pulse" />Lab scope locked<div className="scope-code">192.168.56.0/24<br />10.10.10.0/24</div></div>
      </aside>

      <main className="main-content">
        <header className="topbar"><div><span className="eyebrow">Purple team workspace / 08.12.2026</span><h1>Mission control</h1></div><div className="top-actions"><div className="api-status"><span className={apiOnline ? "status-pulse" : "status-pulse muted"} />{apiOnline ? "API online" : "Demo mode"}</div><button className="ghost-button" onClick={runDryRecon} disabled={busy}>{busy ? "Planning…" : "Run safe recon"}</button><div className="avatar">AG</div></div></header>

        <section id="overview" className="hero-banner"><div><span className="eyebrow accent">LAB-ONLY / DRY-RUN DEFAULT</span><h2>From exposed identity to<br /><em>domain control.</em></h2><p>Model attack paths, validate detections, and turn purple-team evidence into remediation priorities.</p></div><div className="hero-stat"><span className="eyebrow">Current posture</span><strong>High risk</strong><span>3 critical chokepoints</span></div></section>

        <section className="metric-grid" aria-label="Risk summary"><MetricCard label="Risk score" value="78 / 100" tone="danger" note="+12 since last run" /><MetricCard label="Assets observed" value="24" tone="cyan" note="6 identity-bearing" /><MetricCard label="Open findings" value="09" tone="amber" note="3 high · 1 critical" /><MetricCard label="Detection coverage" value="66.7%" tone="lime" note="2 of 3 mapped techniques" /></section>

        <section className="content-grid">
          <article id="attack-graph" className="panel graph-panel"><div className="panel-heading"><div><span className="eyebrow">Path analysis / weighted graph</span><h3>Shortest route to Domain Admin</h3></div><span className="panel-tag">DIJKSTRA + CENTRALITY</span></div><AttackPathGraph nodes={graphNodes} edges={graphEdges} /><div className="legend"><span><i className="legend-dot observed" />Observed asset</span><span><i className="legend-dot chokepoint" />Chokepoint</span><span><i className="legend-dot goal" />Privilege goal</span></div></article>
          <article id="coverage" className="panel coverage-panel"><div className="panel-heading"><div><span className="eyebrow">Purple-team validation</span><h3>Detection coverage</h3></div><span className="coverage-number">66.7%</span></div><div className="coverage-ring"><div><strong>2/3</strong><span>techniques covered</span></div></div><div className="coverage-list">{coverage.map((item) => <div className="coverage-row" key={item.id}><span className={`coverage-state ${item.state}`} /><div><strong>{item.id} · {item.name}</strong><small>{item.detail}</small></div><span className={`coverage-label ${item.state}`}>{item.state}</span></div>)}</div></article>
        </section>

        <section id="findings" className="panel findings-panel"><div className="panel-heading"><div><span className="eyebrow">Prioritized remediation queue</span><h3>Critical findings</h3></div><a className="text-link" href="#reports">View all findings →</a></div><div className="finding-table"><div className="finding-head"><span>Finding</span><span>MITRE mapping</span><span>Asset</span><span>Severity</span></div><div className="finding-row"><div><strong>Certificate template permits subject control</strong><small>Authentication certificate can become a privileged identity</small></div><span className="technique">T1649</span><span>CA-01</span><span className="severity critical">Critical</span></div><div className="finding-row"><div><strong>Service principal name on high-value account</strong><small>Review account secret strength and delegation exposure</small></div><span className="technique">T1558.003</span><span>DC-01</span><span className="severity high">High</span></div><div className="finding-row"><div><strong>Kerberos pre-authentication disabled</strong><small>AS-REP response may be exposed to offline guessing</small></div><span className="technique">T1558.004</span><span>USER-07</span><span className="severity high">High</span></div></div></section>

        <section className="action-strip"><div><span className="eyebrow">Latest activity</span><strong>{lastAction}</strong></div><div className="action-buttons"><button className="secondary-button" onClick={() => setLastAction("Report generation queued for current evidence set.")}>Generate report</button><button className="primary-button" onClick={runDryRecon}>Review run</button></div></section>
        <footer className="footer"><span>REDPATH v0.1.0</span><span>Audit chain healthy · Scope policy enforced · No credentials stored</span></footer>
      </main>
    </div>
  );
}

export default App;
