# RedPath API design

The API is versioned under `/api/v1` and returns JSON models that are stable enough for the React console and future CLI clients. All write-like operations create an audit record. The API is intentionally read-mostly with respect to external systems: Wazuh querying is read-only, while report generation only writes a local artifact. Except for health, one-time bootstrap, and token issuance, endpoints require a bearer session and tenant-aware RBAC; see [Identity, tenancy, RBAC, and API protection](identity-rbac.md).

| Method | Endpoint | Purpose | Safety behavior |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | Service health and default mode | Public liveness check; no external side effect |
| POST | `/api/v1/auth/bootstrap` | Create the first tenant and administrator session | One-time, configuration-gated, rate-limited |
| POST | `/api/v1/auth/token` | Issue a short-lived opaque bearer session | Rate-limited; raw token is not persisted |
| GET | `/api/v1/auth/me` | Inspect the authenticated principal and tenant | Requires bearer authentication |
| POST | `/api/v1/auth/tenants` | Provision a tenant and initial local administrator | Platform-admin role required |
| GET/POST | `/api/v1/auth/users` | List or create users in the current tenant | Tenant-admin or platform-admin role required |
| GET | `/api/v1/scope` | Show allowed CIDRs and dry-run default | Does not expose credentials |
| GET | `/api/v1/techniques` | Return supported MITRE mappings | Static registry read |
| GET | `/api/v1/scenarios` | Return curated safe assessment playbooks | Static catalog read |
| GET | `/api/v1/runs` | Return recent persisted assessment summaries | Local SQLite read |
| GET/POST | `/api/v1/campaigns` | Create and list bounded assessment campaigns | Local metadata only; audit logged |
| POST | `/api/v1/campaigns/{campaign_id}/runs/{run_id}` | Link a completed scenario run to a campaign | Validates both IDs; no rerun |
| GET | `/api/v1/campaigns/{campaign_id}/timeline` | Return ordered campaign evidence and remediation events | Local SQLite read |
| GET | `/api/v1/campaigns/{campaign_id}/export` | Build a deterministic JSON campaign package | Read-only; returns manifest digest |
| POST | `/api/v1/recon` | Plan or run safe discovery | Validates every IP; dry-run wins over requested execution |
| POST | `/api/v1/detections/ad` | Analyze exported AD observations | No AD connection; no attack execution |
| POST | `/api/v1/risk/correlate` | Combine finding severity/CVSS and path relevance | Pure in-memory analysis |
| POST | `/api/v1/scenarios/{scenario_id}/run` | Execute a safe evidence-driven scenario | Dry-run default; persists local summary only |
| GET/POST | `/api/v1/evidence` | Register and list provenance metadata for imported evidence | Stores hash and metadata, never credentials |
| GET | `/api/v1/evidence/{evidence_id}/manifest` | Generate canonical evidence manifest | Pure local hashing; no file execution |
| GET/POST | `/api/v1/remediations` | Create and list remediation ownership items | Local workflow state; audit logged |
| GET | `/api/v1/remediations/sla` | Classify remediation SLA posture | Deterministic policy; no silent due-date changes |
| GET | `/api/v1/integrity/audit` | Verify the chained JSONL audit log | Read-only integrity verification |
| GET | `/api/v1/trends/risk` | Aggregate persisted risk and coverage by period | Derived from stored run records |
| GET | `/api/v1/detection-tuning` | Return gap-driven rule-tuning queue | Recommendations only; no Wazuh mutation |
| POST | `/api/v1/graph/analyze` | Compute shortest path and chokepoints | Pure in-memory analysis |
| POST | `/api/v1/purple/analyze` | Compare expected techniques against Wazuh-style alerts | Accepts imported evidence; no rule changes |
| POST | `/api/v1/reports/pdf` | Generate a local PDF from findings and optional coverage | No external side effect |

## Recon request

```json
{
  "targets": ["192.168.56.10"],
  "profile": "service_inventory",
  "dry_run": true
}
```

The response returns a `scan_id`, the normalized targets, the generated argument arrays, any parsed assets, and warnings. The `profile` is deliberately constrained to `safe` and `service_inventory`; there is no endpoint for arbitrary command text or exploit scripts.

## AD observation request

```json
[
  {"asset_id": "dc01", "service_principal_name": "MSSQLSvc/db01.lab.local:1433"},
  {"asset_id": "user07", "preauth_disabled": true},
  {"asset_id": "ca01", "enrollee_supplies_subject": true, "client_auth_eku": true}
]
```

Each observation becomes a typed finding with severity, evidence, CVSS score and vector, and a MITRE technique ID. The initial registry maps Kerberoasting to `T1558.003`, AS-REP Roasting to `T1558.004`, and authentication-certificate abuse to `T1649`.

## Scenario execution request

```json
{
  "scenario_id": "ad.identity-exposure-baseline",
  "observations": [
    {"asset_id": "DC-01", "service_principal_name": "MSSQLSvc/db01.lab.local:1433"},
    {"asset_id": "USER-07", "preauth_disabled": true}
  ],
  "alerts": [
    {"id": "alert-001", "rule": {"description": "T1558.003 Kerberoasting signal"}}
  ],
  "dry_run": true
}
```

The scenario response combines findings, coverage, detection gaps, recommendations, and an explainable risk score. The run is persisted to `data/redpath.db` with no credentials or raw attack commands. `GET /api/v1/runs` returns summaries for the dashboard history view.

## Expert operations workflow

A campaign is a bounded assessment context with an owner and scope snapshot. Evidence registration requires a source, evidence type, title, SHA-256 digest, and optional run/technique links. Remediation records add ownership, priority, due date, and lifecycle status. Trend points aggregate stored run records by period, while detection-tuning items convert recurring technique gaps into rule intent, event-source, and regression-fixture recommendations. The audit endpoint recomputes each chained digest and identifies the first invalid event. The export endpoint creates a deterministic JSON package with campaign, timeline, evidence, remediation, trend, and tuning sections plus a manifest digest. These operations are metadata and evidence workflows only; RedPath does not modify AD, Wazuh, or external lab systems.

## Purple-team request

```json
{
  "expected_technique_ids": ["T1558.003", "T1558.004", "T1649"],
  "alerts": [
    {"id": "alert-001", "rule": {"description": "T1558.003 Kerberoasting detected"}}
  ],
  "dry_run": true
}
```

The report calculates coverage as detected expected techniques divided by expected techniques. A gap includes the technique ID and a recommendation to tune rules and add a synthetic regression fixture. A future adapter can populate `alerts` from the Wazuh indexer query shown in the lab guide.

## Error semantics

Missing or invalid bearer credentials return HTTP 401 with a bearer challenge. A valid principal without the required role or permission returns HTTP 403, and a bounded request budget returns HTTP 429. A target outside the allow-list also returns HTTP 403. A malformed graph or unknown technique returns HTTP 422. The service returns structured FastAPI validation errors for malformed payloads. Audit events include a request operation, the authenticated actor, the effective dry-run mode, relevant identifiers, and a chained digest.

## Asynchronous discovery jobs and inventory

The discovery module adds a durable, bounded worker boundary for discovery. These endpoints require a bearer token configured with `REDPATH_DISCOVERY_API_TOKEN` and a tenant value matching `REDPATH_DISCOVERY_TENANT_ID` (or the `X-RedPath-Tenant` header when it matches the server-side value). If the token is unset, the endpoints fail closed with HTTP 503 rather than exposing an unauthenticated discovery control plane.

| Method | Endpoint | Purpose | Safety behavior |
| --- | --- | --- | --- |
| POST | `/api/v1/discovery/jobs` | Queue an allow-listed discovery job | Returns HTTP 202; bounded target list; server dry-run wins; fixed argv only; audit logged |
| GET | `/api/v1/discovery/jobs` | List the current tenant’s recent jobs | Tenant-filtered local read; result payloads contain normalized observations only |
| GET | `/api/v1/discovery/jobs/{job_id}` | Read one job lifecycle record | Returns 404 for another tenant or an unknown job |
| GET | `/api/v1/inventory/assets` | Return normalized discovered assets | Tenant-filtered, bounded local read; no credentials or raw command output |

A job transitions through `queued`, `running`, and `completed` or `failed`. The worker persists the scan record and normalizes each observation into the versioned asset identity contract (`schema_version: "1.0"`). Repeated observations for the same tenant and IP update the stable inventory asset identifier rather than creating unbounded duplicates. Discovery is dry-run by default, and the existing safe profile uses a fixed command allow-list with no shell interpolation, exploit scripts, credential operations, or destructive actions.

```json
{
  "targets": ["192.168.56.10"],
  "profile": "safe",
  "dry_run": true
}
```

The response includes `job_id`, lifecycle status, progress, normalized targets, optional `scan_id`, and (after completion) a serialized `ReconResult`. The worker deliberately stores warnings and normalized port/service observations, not stdout/stderr or secrets. Operators should poll the status endpoint with a modest interval and use the inventory endpoint for the current tenant’s asset view.

The database change is represented by `backend/migrations/001_ai03_discovery_jobs.sql`. The application bootstrap also creates the new table for local SQLite deployments, while production deployments should apply the migration through the platform’s migration runner before starting workers.

## Security and operational limits

The worker uses a small bounded thread pool (`REDPATH_RECON_MAX_WORKERS`, default `2` and capped at `4`), a per-command timeout (`REDPATH_RECON_TIMEOUT_SECONDS`, default `30`), a per-tenant submission rate limit (`REDPATH_DISCOVERY_MAX_JOBS_PER_MINUTE`, default `30`), and Pydantic validation limiting each request to 64 IP targets. The configured CIDR allow-list is checked before a job is persisted. Audit events record queue, rejection, completion, and failure metadata while excluding raw payloads. This module uses a single token-bound configured tenant as a fail-closed bridge until the shared identity/RBAC module supplies the platform-wide authorization provider.
