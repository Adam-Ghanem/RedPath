# RedPath roadmap

RedPath is intentionally staged as a **lab-only attack-path simulator and purple-team evidence platform**. The roadmap prioritizes a working, reviewable foundation before deeper integrations. It does not include exploit payloads, credential theft, persistence, evasion, or production-target automation.

| Release | Outcome | Scope | Portfolio signal |
| --- | --- | --- | --- |
| MVP | Safe assessment loop | FastAPI service, strict CIDR allow-list, dry-run recon planning, observation-based AD checks, MITRE registry, NetworkX shortest path and chokepoints, SQLite schema, React dashboard, tests | Demonstrates Python engineering, secure defaults, threat-informed analysis, and full-stack delivery |
| v1 | Repeatable purple-team workflow | Read-only Wazuh indexer adapter, imported alert correlation, detection-gap reports, PDF export, synthetic Windows event fixtures, custom Wazuh rule examples, CI with Ruff/Pytest/Bandit/Semgrep | Demonstrates SOC integration, detection engineering, evidence handling, and reporting |
| v2 | Extensible lab platform | Plugin SDK, scheduled lab runs, multi-tenant project separation, graph snapshots, environmental risk modifiers, ADCS template inventory, signed run artifacts, richer React graph controls | Demonstrates platform architecture, operational maturity, and research-ready extensibility |

## MVP acceptance criteria

The MVP is complete when a reviewer can start the API, open the console, inspect a seeded attack graph, call the dry-run recon endpoint, submit synthetic AD observations, inspect MITRE-linked findings, and see a coverage report without providing credentials or touching a non-lab address.

## v1 acceptance criteria

The first production-like milestone is complete when a reviewer can point RedPath at a read-only Wazuh indexer, bound the query to a time window, compare expected techniques against alert evidence, inspect missed detections, export a PDF, and reproduce the run from an audit record.

## v2 acceptance criteria

The second milestone is complete when new detection or recon modules can be added without modifying the core orchestration layer, graph snapshots are versioned, and the platform can explain why each remediation priority changed over time.
