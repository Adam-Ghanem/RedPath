# Telemetry correlation and case projections

RedPath exposes normalized Wazuh telemetry to detection and case workflows through bounded, read-only projections. The integration operates only on telemetry already persisted in the tenant-scoped local database. It does not send writes, updates, deletes, active-response requests, agent commands, or configuration changes to the Wazuh Indexer.

## Authenticated API surface

| Endpoint | Permission | Purpose |
| --- | --- | --- |
| `POST /api/v1/siem/telemetry/detections/evaluate` | `analyze` | Evaluate registered detection rules against normalized telemetry in a bounded time window. |
| `GET /api/v1/siem/telemetry/evidence` | `read` | Return evidence-ready projections for case review without creating or mutating case records. |
| `GET /api/v1/siem/telemetry/health` | `read` | Return tenant-scoped ingestion freshness, counts, and safe status diagnostics. |

The authenticated principal supplies the tenant and actor identity. The detection request contains only a time window, optional registered rule IDs, and a bounded result limit; it cannot select a tenant, Wazuh URL, credential, raw query, or arbitrary provider field. Audit entries use the server-derived principal username and contain aggregate counts rather than event payloads.

## Correlation projection

The persisted `TelemetryEvent` remains the canonical analyst-safe record. Detection evaluation converts it to the existing `WazuhAlert` contract using only these allow-listed fields:

| Normalized field | Detection path | Notes |
| --- | --- | --- |
| `rule_description` | `rule.description` | Bounded rule description used by registered rules. |
| `source` | `rule.source` and `data.source` | Fixed to `wazuh`. |
| `correlation_fields.event_id` | `data.event_id` | Bounded event identifier such as Windows Event ID. |
| `correlation_fields.srcuser` | `data.srcuser` | Bounded source account identifier. |
| `correlation_fields.dstuser` | `data.dstuser` | Bounded destination account identifier. |
| `correlation_fields.host` | `data.host` | Bounded host label. |
| `correlation_fields.preauth_required` | `data.preauth_required` | Boolean detection signal. |
| `correlation_fields.enrollee_supplies_subject` | `data.enrollee_supplies_subject` | Boolean detection signal. |
| `correlation_fields.client_auth_eku` | `data.client_auth_eku` | Boolean detection signal. |

No `full_log`, command, password, token, authorization header, arbitrary nested provider object, or raw HTTP response is included in the projection. Values are type- and length-bounded before persistence.

## Bounds and deduplication

All correlation and evidence queries require timezone-aware start and end values, reject reversed windows, and cap the window at 24 hours. Result limits are clamped to 1–1,000. Technique filters are validated against the MITRE technique identifier shape and capped at 50 values. The Wazuh adapter uses exact term filters, bounded result sizes, deterministic timestamp and `_id` sorting, and only the `wazuh-alerts*` search endpoint.

Ingestion remains idempotent through the tenant-scoped event identifier. Replaying the same Wazuh page stores no second event and increments the ingestion run’s deduplication counter. Detection evaluation loads the deduplicated local rows, so replay does not amplify alert evidence or case projections.

## Case evidence and health

The evidence endpoint returns immutable projections containing the event ID, tenant, observed time, severity, title, technique IDs, asset ID, rule ID, and raw-payload hash. It does not create evidence records, change review state, assign a reviewer, or trigger remediation. Case creation and review remain behind the existing `manage_cases` authorization and audit controls.

Health diagnostics are tenant-scoped and report `unknown` when no run exists, `healthy` when the latest run’s fetched count equals stored plus deduplicated counts, and `degraded` when counters are inconsistent. The response includes the latest run, event freshness, cumulative counts, and deduplication totals. It contains no raw provider errors or payloads.

## Integration limits

The projection bridge intentionally supports the current registered detection-rule engine and does not execute rule text, shell commands, network actions, or remote SIEM operations. It does not infer missing fields, expand arbitrary provider schemas, or replace independent evidence review. Detection rules remain subject to their existing registration and approval lifecycle. Any future mutation, deployment, or remediation action requires its existing authenticated route, role permission, dry-run policy, and audit trail.
