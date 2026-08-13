# AI-07 Attack-Path Graph and Explainable Risk Engine

## Purpose

The AI-07 vertical slice analyzes a **caller-supplied defensive graph** and returns ranked attack paths, explainable risk factors, defensive choke points, hybrid cloud-path labels, and negative findings for crown jewels with no viable path. It is intentionally read-only: the service does not scan, connect to graph nodes, execute commands, access credentials, or infer relationships from outside the submitted graph.

The implementation is exposed through `POST /api/v1/attack-paths/analyze` and is implemented in `backend/app/services/attack_path_risk.py`. The Pydantic request and response contracts are in `backend/app/schemas/contracts.py`.

## Contract and safety boundaries

| Boundary | Implementation |
| --- | --- |
| Tenant context | `tenant_id` is required on every analysis request and is echoed in the response. A future persistence layer must use it as a server-side resource-isolation key. |
| Scope | Only nodes and edges present in the request are analyzed. Unknown edge endpoints are rejected. |
| Resource limits | `max_hops` is capped at 12, `max_paths` at 500, nodes at 5,000, and edges at 20,000. Enumeration stops at the path cap and reports truncation. |
| Sensitive data | Audit records contain tenant and aggregate counts only. The service does not log node labels, metadata, prerequisites, or raw evidence. |
| Execution | No network, shell, credential, persistence, evasion, exploit, or destructive operation is present in the module. |
| Determinism | Path IDs are stable hashes of ordered node IDs. Results are sorted by composite score, impact, path length, and path ID. |

The new route requires `require_authenticated_analyst`, which resolves a principal injected by platform authentication middleware and rejects missing authentication or unapproved roles. `authorize_tenant` then enforces tenant/resource isolation, with `platform_admin` as the only cross-tenant role. The route also records an aggregate-only audit event. The current prototype still needs to connect its real authentication middleware to `request.state.principal`; no request header is trusted by this module.

## Input model

Each `AttackNode` has a stable ID, display label, asset kind, criticality, zone, and optional entry-point or crown-jewel flags. Each `AttackEdge` represents an already-authorized relationship or observed defensive finding. It carries a path category, MITRE technique identifiers, prerequisites, a rationale, hardening action, and three normalized scores from 0 to 10:

- **Likelihood** represents prerequisite availability. Higher values mean fewer or weaker prerequisites.
- **Impact** represents potential defensive consequence. Higher values indicate closer proximity to a crown jewel or greater privilege.
- **Stealth** is an inverted detection-probability score. Higher values mean lower expected detection.

An analysis request may provide explicit `entry_point_ids` and `crown_jewel_ids`. If those lists are empty, the engine derives them from node flags. At least one of each is required. A crown jewel that cannot be reached from any entry point is returned in `unreachable_crown_jewels` rather than silently omitted.

## Risk calculation

For every simple path within `max_hops`, the engine uses the most conservative edge-level value for likelihood and stealth, and the highest impact across edges and terminal-node criticality. This makes a path explainable without pretending that one average score represents every hop:

```text
path_likelihood = min(edge.likelihood)
path_impact     = max(max(edge.impact), terminal_criticality * 10)
path_stealth    = min(edge.stealth)
composite       = (path_likelihood * 0.40)
                + (path_impact     * 0.40)
                + (path_stealth    * 0.20)
risk_score      = composite * 10
```

The response includes the three factors, their weights, weighted contributions, assumptions, and mitigation actions. Scores at or above `critical_threshold` (default `7.0`) are treated as critical paths for choke-point analysis. Risk levels are `critical` at 7.0 or above, `high` at 5.0–6.99, `medium` at 3.0–4.99, and `low` below 3.0.

## Prioritization outputs

The engine returns all viable paths up to the caller's safe cap, sorted highest risk first. A path is marked hybrid when any edge is explicitly `hybrid` or its nodes span more than one zone. Hybrid path IDs are returned in `cloud_paths` so downstream reporting can prioritize on-premises-to-cloud crossings without losing the underlying explanation.

A choke point is an internal node appearing in one or more critical paths. Its priority is deterministic: P0 for five or more blocked critical paths, P1 for three or four, and P2 for one or two. Each record includes the affected path IDs, a hardening action, estimated effort, and rationale. Nodes that occur only on non-critical paths are not reported as critical choke points.

## Integration points

| Consumer | Contract field | Intended use |
| --- | --- | --- |
| Asset inventory | `AttackNode` plus AI-01 `Asset` identifiers | Build a tenant-scoped graph without changing the shared asset contract. |
| Detection engineering | `mitre_techniques`, `prerequisites`, and `explanation.factors` | Identify detection gaps and produce regression fixtures. |
| Findings and remediation | `path_id`, `choke_points`, `hardening_action`, and `estimated_effort_hours` | Create evidence-backed defensive findings that reference the exact paths they address. |
| Analyst console | `ranked_paths`, `cloud_paths`, `unreachable_crown_jewels`, and `warnings` | Render a ranked, explainable view without exposing raw sensitive payloads in audit logs. |
| Audit and observability | Aggregate route audit event | Track tenant, graph size, viable paths, and critical paths. |

## Validation

Focused tests are in `backend/tests/test_attack_path_risk.py`. They cover weighted scoring and explanations, deterministic ranking, hybrid path labeling, choke-point priority, unreachable crown-jewel reporting, endpoint validation, and resource-limit validation. Existing graph, correlation, API, and AI-01 contract tests remain part of the regression suite.
