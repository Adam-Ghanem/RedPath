import AttackPathGraph from "./components/AttackPathGraph";
import {
  ArrowDownRight,
  ArrowUpRight,
  BookOpen,
  Boxes,
  CheckCircle2,
  ChevronRight,
  CircleDotDashed,
  Code2,
  Command,
  Crosshair,
  FileCode2,
  FileText,
  GitPullRequest,
  LayoutDashboard,
  Network,
  Radar,
  Search,
  ShieldCheck,
  ShieldAlert,
  TerminalSquare,
  UsersRound,
} from "lucide-react";
import { useMemo, useState } from "react";
import { coverageByTactic, findings, graphNodes, mitreCoverage, overallCoverage, pathById, scenarios, type Severity } from "./data/redpathDemo";

const severityOrder: Severity[] = ["Critical", "High", "Medium", "Low"];

export default function Home() {
  const [selectedPathId, setSelectedPathId] = useState("path-service-ticket");
  const [selectedAssetId, setSelectedAssetId] = useState("SVC-BACKUP");
  const [selectedScenarioId, setSelectedScenarioId] = useState("service-ticket");
  const [severityFilter, setSeverityFilter] = useState<Severity | "All">("All");
  const [search, setSearch] = useState("");
  const selectedScenario = scenarios.find((scenario) => scenario.id === selectedScenarioId) ?? scenarios[0];
  const selectedPath = pathById(selectedPathId);
  const selectedAsset = graphNodes.find((node) => node.id === selectedAssetId) ?? graphNodes[0];
  const coverage = overallCoverage();
  const filteredFindings = useMemo(() => findings.filter((finding) => {
    const matchesSeverity = severityFilter === "All" || finding.severity === severityFilter;
    const haystack = `${finding.asset} ${finding.title} ${finding.technique}`.toLowerCase();
    return matchesSeverity && haystack.includes(search.toLowerCase());
  }), [severityFilter, search]);

  const launchScenario = (scenarioId: string) => {
    const scenario = scenarios.find((candidate) => candidate.id === scenarioId) ?? scenarios[0];
    setSelectedScenarioId(scenario.id);
    setSelectedPathId(scenario.pathId);
    document.getElementById("explore")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className="redpath-app">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="RedPath home"><span className="brand-mark"><img className="brand-logo" src="/assets/redpath-logo-transparent.png" alt="" /></span><span>REDPATH</span><small>v0.1.0</small></a>
        <nav className="site-nav" aria-label="Primary navigation">
          <a href="#explore">Console</a><a href="#coverage">Coverage</a><a href="#findings">Findings</a><a href="#scenarios">Scenarios</a><a href="#github">GitHub</a>
        </nav>
        <a className="header-cta" href="#explore">Explore lab <ArrowDownRight size={15} /></a>
      </header>

      <main id="top">
        <section className="hero section-shell">
          <div className="case-index-rail" aria-hidden="true"><span>01</span><span>02</span><span>03</span><span>04</span></div>
          <div className="hero-copy">
            <div className="eyebrow"><span className="pulse-dot" /> Case RP-101 · Cyber risk briefing</div>
            <h1>Every path<br />leaves <em>evidence.</em></h1>
            <p className="hero-lede">RedPath maps synthetic Active Directory trust paths, exposes critical risk, and turns technical evidence into a precise remediation decision.</p>
            <div className="case-file-badge"><div><span>CASE ID</span><strong>RP-101</strong></div><div><span>STATUS</span><b>ACTIVE</b></div></div>
            <div className="hero-actions"><a className="button primary" href="#explore"><Crosshair size={16} /> Open interactive lab</a><a className="button secondary" href="#github"><GitPullRequest size={16} /> View repository assets</a></div>
            <div className="hero-proof"><span><CheckCircle2 size={15} /> 100% synthetic lab data</span><span><CheckCircle2 size={15} /> zero configuration</span><span><CheckCircle2 size={15} /> safe dry-run only</span></div>
          </div>
          <div className="hero-panel" aria-label="RedPath evidence board attack path diagram">
            <div className="case-board">
              <div className="case-board-head"><span>ATTACK PATH DIAGRAM / RP-101</span><b>CRITICAL</b></div>
              <div className="case-board-route">
                <svg viewBox="0 0 520 300" aria-hidden="true"><path d="M47 103 H165 L227 64 H354 L448 38 V166 L405 208 H267 L224 250" /><path className="inferred" d="M165 103 L224 179 L302 179" /><circle className="hot" cx="47" cy="103" r="7" /><circle cx="165" cy="103" r="7" /><circle className="hot" cx="227" cy="64" r="7" /><circle cx="354" cy="64" r="7" /><circle className="hot" cx="448" cy="38" r="7" /><circle cx="405" cy="208" r="7" /><circle className="hot" cx="224" cy="250" r="7" /></svg>
                <div className="board-point initial hot">Initial access<b>WS-21</b><small>Finance workstation</small></div><div className="board-point credential">Credential access<b>svc-backup</b><small>Recoverable ticket</small></div><div className="board-point privilege hot">Privilege escalation<b>Tier-0</b><small>Delegated control</small></div><div className="board-point discovery">Discovery<b>Directory map</b><small>Inferred relationship</small></div><div className="board-point lateral">Lateral movement<b>APP-01</b><small>Admin share route</small></div><div className="board-point exfil hot">Exposure confirmed<b>DC-01</b><small>Directory control</small></div>
              </div>
              <div className="board-legend"><span>Observed</span><span>Inferred</span><span>Evidence point</span></div>
            </div>
          </div>
          <aside className="case-evidence-rail" aria-label="Evidence cards">
            <div className="evidence-stamp">EVIDENCE<small>HANDLE WITH CARE</small></div>
            <article className="evidence-card"><span>EVIDENCE 01</span><b>Credential exposure</b><p>Service identity delegation path observed in the synthetic lab.</p><em>RP-101 · 9.1 CVSS</em></article>
            <article className="evidence-card"><span>EVIDENCE 02</span><b>Coverage gap</b><p>No correlated alert for the service-ticket exposure path.</p><em>T1558.003</em></article>
            <article className="evidence-card"><span>EVIDENCE 03</span><b>Remediation</b><p>Rotate credential and remove unconstrained delegation.</p><em>OWNER: IDENTITY OPS</em></article>
          </aside>
        </section>

        <section className="trust-strip"><span>Built for clear security conversations</span><div><span><Network size={16} /> Attack path reasoning</span><span><Radar size={16} /> Purple-team evidence</span><span><ShieldCheck size={16} /> Safe demonstration mode</span><span><FileCode2 size={16} /> GitHub-ready from day one</span></div></section>

        <section className="features section-shell" id="product">
          <div className="section-heading"><div><span className="section-index">01 / PRODUCT SURFACE</span><h2>A security project that <em>explains itself</em> in one screen.</h2></div><p>Every surface connects a finding to a path, a technique, the supporting evidence, and a defensible next action.</p></div>
          <div className="feature-grid">
            <article className="feature-card feature-major"><div className="feature-icon"><GitPullRequest size={20} /></div><span className="feature-number">01</span><h3>Weighted attack paths</h3><p>Move beyond a flat asset inventory. Surface the lowest-cost route to a high-value target, then show the chokepoints that matter most.</p><div className="mini-path"><span>USER ZONE</span><i /><span>TRUST EDGE</span><i /><b>TIER-0</b></div></article>
            <article className="feature-card"><div className="feature-icon"><Radar size={20} /></div><span className="feature-number">02</span><h3>Coverage as evidence</h3><p>Map expected behaviors to MITRE ATT&amp;CK, correlate synthetic alert evidence, and make the gaps immediately visible.</p></article>
            <article className="feature-card"><div className="feature-icon"><ShieldAlert size={20} /></div><span className="feature-number">03</span><h3>Safe scenario playbooks</h3><p>Every scenario is dry-run by default. The UI reveals plans and evidence without operating against a live environment.</p></article>
            <article className="feature-card"><div className="feature-icon"><UsersRound size={20} /></div><span className="feature-number">04</span><h3>Decision-ready findings</h3><p>CVSS, MITRE mapping, evidence, ownership context, and remediation guidance sit together instead of across disconnected tools.</p></article>
          </div>
        </section>

        <section className="architecture section-shell">
          <div className="section-heading compact"><div><span className="section-index">02 / ARCHITECTURE</span><h2>From synthetic observation to <em>explainable action.</em></h2></div></div>
          <div className="architecture-diagram" role="img" aria-label="RedPath architecture diagram">
            <div className="arch-stage"><span className="arch-id">01</span><TerminalSquare size={21} /><b>Synthetic lab signals</b><small>AD objects · sessions · group edges · alerts</small></div><ChevronRight className="arch-arrow" /><div className="arch-stage"><span className="arch-id">02</span><Boxes size={21} /><b>Exposure reasoning</b><small>Weighted graph · CVSS · MITRE registry</small></div><ChevronRight className="arch-arrow" /><div className="arch-stage"><span className="arch-id">03</span><LayoutDashboard size={21} /><b>Decision console</b><small>Paths · gaps · owners · safe playbooks</small></div>
          </div>
          <div className="quickstart-block"><div className="quickstart-copy"><span className="eyebrow"><Command size={14} /> Quick start</span><h3>Clone, launch, explore.</h3><p>The demo starts with pre-seeded lab data. No API keys, agents, or directory access are required.</p></div><pre><code><span className="code-comment"># zero-config interactive security demo</span>{"\n"}git clone https://github.com/Adam-Ghanem/RedPath.git{"\n"}cd RedPath && docker compose up --build{"\n\n"}<span className="code-comment"># then open the console</span>{"\n"}open http://localhost:5173</code></pre></div>
        </section>

        <section className="console-section" id="explore">
          <div className="section-shell"><div className="console-head"><div><span className="section-index">03 / INTERACTIVE LAB</span><h2>Explore the <em>trust map.</em></h2></div><div className="live-pill"><span className="pulse-dot" /> Demo mode: seeded synthetic domain</div></div><AttackPathGraph selectedPathId={selectedPathId} selectedAssetId={selectedAssetId} onSelectPath={setSelectedPathId} onSelectAsset={setSelectedAssetId} /></div>
        </section>

        <section className="coverage-section section-shell" id="coverage">
          <div className="section-heading"><div><span className="section-index">04 / DETECTION COVERAGE</span><h2>Turn purple-team evidence into <em>clear coverage.</em></h2></div><p>Each expected technique is paired with observed detection evidence so gaps are grounded in a repeatable, safe lab workflow.</p></div>
          <div className="coverage-layout"><article className="coverage-summary"><div className="coverage-dial" style={{ background: `conic-gradient(#66e3a5 0 ${coverage}%, #1a3040 ${coverage}% 100%)` }}><div><strong>{coverage}%</strong><span>overall coverage</span></div></div><div className="coverage-callout"><span className="metric-label">Purple-team finding</span><h3>3 gaps require<br />detection engineering.</h3><p>Certificate template conditions and service-ticket exposure do not yet have correlated alerts.</p><a href="#scenarios">Review playbooks <ArrowUpRight size={14} /></a></div></article>
            <article className="coverage-bars"><div className="card-head"><span>Coverage by ATT&amp;CK tactic</span><span className="muted">DETECTED / EXPECTED</span></div>{coverageByTactic.map((item) => <div className="tactic-row" key={item.tactic}><div className="tactic-label"><span>{item.tactic}</span><b>{item.detected} / {item.expected}</b></div><div className="progress-track"><div style={{ width: `${item.percent}%`, background: item.color }} /></div><small>{item.percent}%</small></div>)}</article>
          </div>
          <div className="mitre-table" aria-label="MITRE ATT&CK coverage map"><div className="mitre-row mitre-header"><span>Technique</span><span>Coverage verdict</span><span>Evidence state</span></div>{mitreCoverage.map((item) => <div className="mitre-row" key={item.technique}><div><b>{item.technique}</b><small>{item.name}</small></div><span className={`coverage-badge ${item.status.toLowerCase()}`}>{item.status}</span><p>{item.detail}</p></div>)}</div>
        </section>

        <section className="findings-section" id="findings"><div className="section-shell"><div className="section-heading"><div><span className="section-index">05 / ASSETS &amp; FINDINGS</span><h2>Every risk arrives with <em>its proof.</em></h2></div><p>Select an asset in the graph or use the explorer to connect technical evidence to a precise remediation decision.</p></div>
          <div className="asset-focus"><div className="asset-symbol"><ShieldAlert size={25} /></div><div><span className="metric-label">Graph selection</span><h3>{selectedAsset.label} <small>{selectedAsset.subtitle}</small></h3></div><div className="asset-status"><span className={`severity-square ${selectedAsset.severity.toLowerCase()}`} /> {selectedAsset.severity} risk node</div><button onClick={() => setSelectedAssetId("SVC-BACKUP")}>Reset selection</button></div>
          <div className="finding-controls"><div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search asset, technique, or finding" aria-label="Search findings" /></div><div className="filter-group" aria-label="Filter severity">{["All", ...severityOrder].map((level) => <button key={level} className={severityFilter === level ? "active" : ""} onClick={() => setSeverityFilter(level as Severity | "All")}>{level}</button>)}</div></div>
          <div className="findings-layout"><div className="finding-list">{filteredFindings.map((finding) => <button className={`finding-row ${finding.asset === selectedAssetId ? "selected" : ""}`} key={finding.id} onClick={() => setSelectedAssetId(finding.asset)}><span className={`severity-square ${finding.severity.toLowerCase()}`} /><span className="finding-meta"><strong>{finding.title}</strong><small>{finding.id} · {finding.asset} · {finding.technique}</small></span><span className="cvss">{finding.cvss}<small>CVSS</small></span><ChevronRight size={15} /></button>)}{filteredFindings.length === 0 && <div className="empty-state">No findings match this filter.</div>}</div><aside className="finding-detail"><span className="detail-kicker"><FileText size={14} /> Evidence dossier</span>{(() => { const finding = findings.find((candidate) => candidate.asset === selectedAssetId) ?? findings[0]; return <><h3>{finding.title}</h3><div className="detail-tags"><span className={`coverage-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><span>{finding.technique}</span><span>CVSS {finding.cvss}</span></div><div className="detail-block"><b>Supporting evidence</b><p>{finding.evidence}</p></div><div className="detail-block remediation"><b>Recommended remediation</b><p>{finding.remediation}</p></div></>; })()}</aside></div>
        </div></section>

        <section className="scenarios-section section-shell" id="scenarios"><div className="section-heading"><div><span className="section-index">06 / SAFE SCENARIOS</span><h2>Four playbooks. <em>Every detail visible.</em></h2></div><p>Designed for authorized lab learning and defensive validation, each playbook remains dry-run and evidence-led.</p></div><div className="scenario-layout"><div className="scenario-list">{scenarios.map((scenario, index) => <button className={`scenario-tab ${selectedScenarioId === scenario.id ? "active" : ""}`} key={scenario.id} onClick={() => setSelectedScenarioId(scenario.id)}><span className="scenario-index">0{index + 1}</span><span><b>{scenario.title}</b><small>{scenario.category}</small></span><span className={`scenario-status ${scenario.status.replace(" ", "-")}`}>{scenario.status}</span></button>)}</div><article className="scenario-detail"><div className="scenario-detail-head"><div><span className="metric-label">{selectedScenario.category}</span><h3>{selectedScenario.title}</h3></div><button className="button small" onClick={() => launchScenario(selectedScenario.id)}>Inspect path <ArrowDownRight size={14} /></button></div><p className="scenario-description">{selectedScenario.description}</p><div className="scenario-columns"><div><span className="detail-kicker"><Crosshair size={14} /> Expected techniques</span>{selectedScenario.expectedTechniques.map((technique) => <div className="technique-chip" key={technique}>{technique}</div>)}</div><div><span className="detail-kicker"><TerminalSquare size={14} /> Dry-run recon plan</span><ol className="recon-plan">{selectedScenario.reconPlan.map((command, index) => <li key={command}><span>{String(index + 1).padStart(2, "0")}</span><code>{command}</code></li>)}</ol></div></div><div className="scenario-risk"><div><span className="detail-kicker"><ShieldAlert size={14} /> Evidence-backed risk summary</span><p>{selectedScenario.riskSummary}</p></div><ul>{selectedScenario.evidence.map((item) => <li key={item}><CheckCircle2 size={15} /> {item}</li>)}</ul></div></article></div></section>

        <section className="github-section" id="github"><div className="section-shell"><div className="github-card"><div className="github-copy"><span className="section-index">07 / GITHUB-READY ASSETS</span><h2>A repository that gives visitors a reason to <em>stay, test, and star.</em></h2><p>RedPath ships with product-grade documentation, clear trust signals, and an explorable demo story designed for the first thirty seconds of a GitHub visit.</p><a className="button primary" href="https://github.com/Adam-Ghanem/RedPath" target="_blank" rel="noreferrer"><GitPullRequest size={16} /> Open RedPath on GitHub</a></div><div className="repo-preview"><div className="repo-bar"><span><GitPullRequest size={15} /> Adam-Ghanem / <b>RedPath</b></span><span className="repo-public">PUBLIC</span></div><div className="repo-badges"><span>MIT LICENSE</span><span>PYTHON 3.11</span><span>REACT + VITE</span><span>SAFE LAB ONLY</span></div><div className="repo-assets"><div><BookOpen size={18} /><b>README</b><small>Badges, product story, docs map</small></div><div><LayoutDashboard size={18} /><b>SCREENSHOTS</b><small>Console, coverage, playbooks</small></div><div><Code2 size={18} /><b>QUICK START</b><small>One command to demo</small></div><div><GitPullRequest size={18} /><b>CONTRIBUTING</b><small>Clear, safe contribution guide</small></div></div><div className="repo-tree"><span>docs/</span><span>frontend/</span><span>backend/</span><span>screenshots/</span><span>README.md</span><span>CONTRIBUTING.md</span></div></div></div></div></section>
      </main>
      <footer className="site-footer"><div><a className="brand" href="#top"><span className="brand-mark"><Network size={16} /></span><span>REDPATH</span></a><p>Exposure path intelligence for safe, repeatable Active Directory lab validation.</p></div><div><span>Demo mode</span><b><i className="status-dot" /> Synthetic data only</b></div><div><span>Selected path</span><b>{selectedPath.name}</b></div></footer>
    </div>
  );
}
