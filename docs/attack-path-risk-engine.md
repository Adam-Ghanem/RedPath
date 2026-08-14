# Attack-Path Graph and Explainable Risk Engine

## Purpose

This capability analyzes a **caller-supplied defensive graph** and returns ranked attack paths, explainable risk factors, defensive choke points, hybrid cloud-path labels, and negative findings for crown jewels with no viable path. It is intentionally read-only: the service does not scan, connect to graph nodes, execute commands, access credentials, or infer relationships from outside the submitted graph.

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

The route requires an authenticated bearer session with the `analyze` permission. It compares the requested tenant with the tenant derived from the authenticated principal and rejects a mismatch. The route also records an aggregate-only audit event; no request header is trusted as an identity source.

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
| Asset inventory | `AttackNode` plus shared `Asset` identifiers | Build a tenant-scoped graph without changing the shared asset contract. |
| Detection engineering | `mitre_techniques`, `prerequisites`, and `explanation.factors` | Identify detection gaps and produce regression fixtures. |
| Findings and remediation | `path_id`, `choke_points`, `hardening_action`, and `estimated_effort_hours` | Create evidence-backed defensive findings that reference the exact paths they address. |
| Analyst console | `ranked_paths`, `cloud_paths`, `unreachable_crown_jewels`, and `warnings` | Render a ranked, explainable view without exposing raw sensitive payloads in audit logs. |
| Audit and observability | Aggregate route audit event | Track tenant, graph size, viable paths, and critical paths. |

## Asset, evidence, and remediation linkage

`AttackNode.asset_id` references the tenant-scoped inventory identity returned by `/api/v1/inventory/assets`. The protected analysis route resolves the authenticated tenant’s inventory server-side and rejects graph references to assets outside that inventory. The shared asset contract remains unchanged.

`AttackEdge.evidence_ids` contains stable references to reviewed evidence records. The protected route resolves those identifiers against the authenticated tenant’s evidence inventory before returning a result. The service returns evidence IDs and aggregate counts only; it does not return evidence notes, packet contents, telemetry payloads, or other raw sensitive data.

Each ranked path receives a stable tenant-scoped `path_id`, an `analysis_id`, and a canonical `graph_fingerprint`. The response carries `asset_ids`, `evidence_ids`, `remediation_priority`, and an explanation of why the priority follows the modeled risk level. `remediation_links` are persistence-ready records containing only tenant, path, asset, evidence, priority, and rationale references. They do not create or mutate remediation records. A server-side adapter may convert these links into the existing remediation workflow after review while preserving the authenticated actor identity.

| Contract | Stability and security behavior |
| --- | --- |
| `analysis_id` | Deterministic for the tenant, graph fingerprint, and bounded analysis parameters |
| `graph_fingerprint` | Canonical hash of tenant-scoped graph nodes and edges; no raw payload is logged |
| `path_id` | Tenant-scoped hash of the ordered path nodes; stable across repeated analysis of the same graph |
| `asset_ids` | Only inventory IDs authorized for the current tenant are accepted |
| `evidence_ids` | Only evidence IDs authorized for the current tenant are accepted and returned |
| `remediation_links` | Read-only, persistence-ready priority/rationale records; no remote mutation or automatic ticket creation |

The route records the server-derived user ID in the in-memory persistence-ready record and uses aggregate-only audit details. Client request fields never determine actor, owner, reviewer, approver, or tenant identity.

## Scale, versioning, and projection interfaces

Every analysis response includes `score_metadata.score_version: "risk-v1"` and `formula: "conservative-edge-v1"`. The weighted formula and factor weights are part of the response contract so downstream consumers can reproduce and regression-test a result without inferring the scoring version from code. A score-version change must be additive or explicitly versioned; it must not silently reinterpret historical results.

The request and response expose effective `query_bounds` and `traversal_steps`. Nodes, edges, hops, paths, explanation characters, and traversal steps are capped. The engine stops path enumeration at either the path or traversal budget and marks the response as truncated with a warning. Truncated results are safe summaries, not exhaustive graph inventories.

`project_attack_path_risk` is a bounded, read-only projection interface for consoles, caches, and exports. It returns at most 50 paths, 50 choke-point IDs, 500 asset IDs, and 500 evidence IDs, and trims each projection rationale to 512 characters. The cache is process-local and keyed by the complete response plus projection limit; returned models are defensive copies, so a caller cannot mutate shared cached state.

`export_attack_path_projection` and `import_attack_path_projection` form a tenant-bound transport contract. Export requires the server-derived tenant, includes a canonical SHA-256 integrity digest, and contains identifiers and rationale only. Import requires the server-derived tenant, checks the envelope analysis ID, and verifies the digest before returning the read-only projection. Neither interface persists data or performs remote mutation.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Graph nodes | 5,000 | 5,000 |
| Graph edges | 20,000 | 20,000 |
| Path hops | 8 | 12 |
| Returned paths | 100 | 500 |
| Traversal steps | 10,000 | 100,000 |
| Explanation text per field | 2,000 | 2,000 |
| Projection paths | 50 | 50 |
| Simulation paths | 100 | 500 |
| Simulation traversal steps | 10,000 | 100,000 |
| Simulation cache entries | 256 | 1,000 |

## Read-only policy simulation

`POST /api/v1/risk/simulate` accepts only an `analysis_id` and bounded policy knobs such as `blocked_technique_ids`. The server resolves the tenant-authoritative minimized snapshot from the registered analysis record; clients cannot supply graph paths, scores, assets, evidence, or rationale. The operation is a deterministic what-if calculation only: a path containing a blocked modeled technique is projected at a conservative 25% of its baseline score, and the response reports per-path score changes and a bounded blast-radius summary.

The response includes effective path/traversal bounds, paths considered, traversal steps, truncation state, duration, a tenant-scoped cache key, and cache-hit status. `RiskCacheInvalidationEvent` is a read-only contract for internal snapshot/policy change notifications; it does not perform remote or database mutation. Query-cost telemetry uses allow-listed aggregate counters and one duration gauge without tenant, analysis, path, asset, evidence, or request labels.

## Validation

Focused tests are in `backend/tests/test_attack_path_risk.py`. They cover weighted scoring and explanations, deterministic ranking, score-version metadata, sensitivity monotonicity, tenant-safe projection caching, import/export integrity, bounded branching fixtures, hybrid path labeling, choke-point priority, unreachable crown-jewel reporting, endpoint validation, and resource-limit validation. Existing graph, correlation, API, and platform-contract tests remain part of the regression suite.

The grounded explanation source registry is introduced by ordered Alembic revision `8f4c1d2a7b90`. The migration is additive and tenant-scoped. Alembic lifecycle checks perform upgrade, downgrade to the prior revision, and re-upgrade. Rollback uses the revision downgrade before code rollback; no destructive data rewrite is performed.

## Grounded AI explanation and opt-out

The optional grounded explanation service is disabled by default with `AI_FEATURES_ENABLED=false`. Operators can opt out permanently by leaving the flag disabled; when disabled, the protected assessment and copilot routes return the deterministic tier, deterministic score, bounded next actions, and an explicit `ai_disabled` fallback status. The deterministic graph engine and detection logic never depend on model availability.

The protected `/api/v1/risk/ai-assess` and `/api/v1/copilot/explain` routes derive tenant and actor context from the authenticated session and require the existing `analyze` permission. Clients submit only `finding_id`, or `analysis_id` plus `path_id`; the server loads findings and registered attack-path summaries with an authenticated-tenant predicate. Scores, tiers, centrality, asset/evidence lists, and rationale are never trusted from the request. Absent or cross-tenant sources return a safe not-found response. Identical sanitized payloads are cached separately per tenant, with bounded TTL and entry count.

External provider context contains only minimized deterministic scores, centrality, hop and count summaries, technique IDs, severity, and categorical evidence-basis tokens. Direct asset IDs, evidence IDs, hostnames, hosts, users, usernames, accounts, principals, IP addresses, credentials, packet data, and raw provider payloads are excluded or pseudonymized before egress. The service sends no context when disabled, and provider failures, timeouts, rate limits, invalid output, or unavailability return deterministic fallback without failing the risk endpoint. Audit records contain aggregate status, score tier, context digest, cache status, and egress mode; they do not contain the prompt or raw evidence. Registration stores only a minimized tenant-bound path summary through the ordered Alembic revision; it has no manual SQL or startup schema side effects.
