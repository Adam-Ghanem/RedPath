# RedPath API design

The API is versioned under `/api/v1` and returns JSON models that are stable enough for the React console and future CLI clients. All write-like operations create an audit record. The API is intentionally read-mostly with respect to external systems: Wazuh querying is read-only, while report generation only writes a local artifact.

| Method | Endpoint | Purpose | Safety behavior |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | Service health and default mode | No external side effect |
| GET | `/api/v1/scope` | Show allowed CIDRs and dry-run default | Does not expose credentials |
| GET | `/api/v1/techniques` | Return supported MITRE mappings | Static registry read |
| GET | `/api/v1/scenarios` | Return curated safe assessment playbooks | Static catalog read |
| GET | `/api/v1/runs` | Return recent persisted assessment summaries | Local SQLite read |
| GET/POST | `/api/v1/campaigns` | Create and list bounded assessment campaigns | Local metadata only; audit logged |
| POST | `/api/v1/campaigns/{campaign_id}/runs/{run_id}` | Link a completed scenario run to a campaign | Validates both IDs; no rerun |
| GET | `/api/v1/campaigns/{campaign_id}/timeline` | Return ordered campaign evidence and remediation events | Local SQLite read |
| POST | `/api/v1/recon` | Plan or run safe discovery | Validates every IP; dry-run wins over requested execution |
| POST | `/api/v1/detections/ad` | Analyze exported AD observations | No AD connection; no attack execution |
| POST | `/api/v1/risk/correlate` | Combine finding severity/CVSS and path relevance | Pure in-memory analysis |
| POST | `/api/v1/scenarios/{scenario_id}/run` | Execute a safe evidence-driven scenario | Dry-run default; persists local summary only |
| GET/POST | `/api/v1/evidence` | Register and list provenance metadata for imported evidence | Stores hash and metadata, never credentials |
| GET/POST | `/api/v1/remediations` | Create and list remediation ownership items | Local workflow state; audit logged |
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

A campaign is a bounded assessment context with an owner and scope snapshot. Evidence registration requires a source, evidence type, title, SHA-256 digest, and optional run/technique links. Remediation records add ownership, priority, due date, and lifecycle status. Trend points aggregate stored run records by period, while detection-tuning items convert recurring technique gaps into rule intent, event-source, and regression-fixture recommendations. These operations are metadata and evidence workflows only; RedPath does not modify AD, Wazuh, or external lab systems.

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

A target outside the allow-list returns HTTP 403. A malformed graph or unknown technique returns HTTP 422. The service returns structured FastAPI validation errors for malformed payloads. Audit events include a request operation, the effective dry-run mode, relevant identifiers, and a chained digest.
