# RedPath v2 platform expansion

RedPath v2 promotes the scenario runner into an operations workspace without changing the safety model. A campaign is a bounded collection of scenario runs. Evidence items are imported observations, alerts, graph references, or report artifacts with provenance and a review state. Remediation items link findings to an owner, priority, due date, and lifecycle status. Trend endpoints derive posture history from persisted assessment runs rather than inventing telemetry.

| Domain | Primary object | v2 behavior |
| --- | --- | --- |
| Campaigns | Campaign | Groups scenario runs under a named assessment objective and scope snapshot |
| Evidence | Evidence item | Stores type, source, hash, provenance, review state, and linked campaign/run IDs; no credentials |
| Remediation | Remediation item | Tracks owner, priority, status, due date, and linked technique/finding |
| Trends | Risk snapshot | Aggregates persisted run scores and coverage by day/campaign for explainable charts |
| Detection engineering | Rule-tuning recommendation | Converts coverage gaps into a review queue with rule intent, event sources, and regression-fixture references |

All write operations create an audit event. The API accepts imported evidence and metadata only. It never executes attack tooling, changes Wazuh rules, creates AD objects, requests tickets, or stores credentials. `dry_run` remains true by default and scope policy continues to apply to any target-bearing request.

## Planned endpoints

`GET/POST /api/v1/campaigns` manages campaign metadata. `POST /api/v1/campaigns/{campaign_id}/runs` associates an existing safe scenario run with a campaign. `GET /api/v1/campaigns/{campaign_id}/timeline` returns ordered run and remediation events. `GET/POST /api/v1/evidence` registers imported evidence metadata and returns a content digest. `GET/POST /api/v1/remediations` manages the remediation queue. `GET /api/v1/trends/risk` returns daily risk and coverage points derived from persisted runs. `GET /api/v1/detection-tuning` returns gap-driven rule-tuning recommendations.

The frontend will present these surfaces as a campaign operations workspace: a campaign header, risk/coverage trend cards, evidence review queue, remediation board, and detection-tuning table. The existing scenario panel remains the entry point for safe evidence-driven runs.
