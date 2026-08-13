# Read-only SIEM/Wazuh telemetry ingestion

AI-05 adds a bounded, tenant-scoped vertical slice for retrieving Wazuh alerts and converting them into analyst-safe RedPath telemetry. The integration performs only an indexer search against the configured `wazuh-alerts*` index pattern. It does not expose an endpoint for alert acknowledgement, rule updates, index writes, agent control, or arbitrary index selection.

## Data flow

```text
Authenticated SOC reader
        |
        | POST /api/v1/siem/telemetry/ingest
        | bearer token + X-RedPath-Tenant
        v
RedPath request validation
        |
        | configured Wazuh URL, server-side credentials, TLS verification
        v
WazuhIndexerClient (read-only _search)
        |
        v
Normalizer and redactor
        |
        | stable event ID, timestamp, severity, rule metadata,
        | MITRE IDs, Wazuh agent asset reference, safe fields, SHA-256
        v
Tenant-scoped local telemetry tables and audit event
```

The query body is constructed by the server. The caller can provide only a tenant ID, timezone-aware time window, allow-listed MITRE technique IDs, and a limit between 1 and 1,000. The configured maximum query window defaults to 24 hours. TLS verification defaults to enabled, and the Wazuh URL and credentials are loaded from server-side settings rather than request data.

## Protected endpoints

| Method | Endpoint | Required authorization | Purpose |
| --- | --- | --- | --- |
| POST | `/api/v1/siem/telemetry/ingest` | Bearer token configured as `SIEM_INGESTION_API_TOKEN` and `X-RedPath-Tenant` in `SIEM_ALLOWED_TENANTS` | Read Wazuh alerts, normalize/redact them, and persist a local ingestion run and event projections |
| GET | `/api/v1/siem/telemetry` | Same bearer token and tenant binding | Read only the redacted local event projections for the authenticated tenant and requested time window |

The request body tenant must equal the authenticated `X-RedPath-Tenant` value. An absent token configuration fails closed with HTTP 503; missing or invalid credentials return HTTP 401; a tenant outside the configured allow-list returns HTTP 403. Secrets are never written to the response or the audit details.

Example ingestion request:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $SIEM_INGESTION_API_TOKEN" \
  -H "X-RedPath-Tenant: lab" \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "lab",
    "start": "2026-08-13T00:00:00Z",
    "end": "2026-08-13T01:00:00Z",
    "technique_ids": ["T1558.003"],
    "limit": 200
  }' \
  https://redpath.example/api/v1/siem/telemetry/ingest
```

## Redaction and evidence semantics

The service does not store the raw Wazuh document. It stores a deterministic SHA-256 digest of the canonical raw document for provenance, together with bounded rule metadata, timestamp, severity, extracted MITRE technique IDs, a Wazuh agent asset reference, and a small allow-list of safe fields (`agent.id`, `agent.name`, `location`, `decoder.name`, and `manager.name`). The response and local database therefore contain a useful correlation projection without copying arbitrary command lines, usernames, file contents, network payloads, or credentials into the analyst surface.

Repeated ingestion of the same tenant/event identity is idempotent. The response reports `fetched_count`, `stored_count`, and `deduplicated_count`, while the audit event records only those counts and the run/tenant identifiers. Local persistence is tenant-indexed, and the readback query always applies the authenticated tenant predicate.

## Configuration

| Setting | Default | Description |
| --- | --- | --- |
| `WAZUH_INDEXER_URL` | `https://wazuh-indexer.local:9200` | Server-side Wazuh indexer URL; must use HTTP or HTTPS |
| `WAZUH_USERNAME` | empty | Server-side read-only Wazuh credential |
| `WAZUH_PASSWORD` | empty | Server-side read-only Wazuh credential; never place in requests or logs |
| `WAZUH_VERIFY_TLS` | `true` | Keep enabled outside a deliberately isolated local fixture |
| `SIEM_INGESTION_API_TOKEN` | empty | Required bearer token; empty means the endpoint fails closed |
| `SIEM_ALLOWED_TENANTS` | `lab` | Comma-separated tenant allow-list |
| `SIEM_MAX_QUERY_WINDOW_HOURS` | `24` | Maximum query window |
| `SIEM_REQUEST_TIMEOUT_SECONDS` | `20` | HTTP client timeout, bounded to 1–120 seconds |

Apply `backend/migrations/001_siem_telemetry.sql` in environments that use an external migration process. Fresh prototype databases continue to use the existing SQLAlchemy metadata creation path, and the model definitions match the migration schema.

## Integration points and limitations

The normalized `TelemetryEvent` contract is intentionally independent from the existing `Asset` contract, but its `asset_id` uses the stable `wazuh-agent:<agent.id>` convention so later asset inventory correlation can link records without re-ingesting raw documents. The existing purple analyzer can consume imported Wazuh-style alerts separately; a future detection-engineering milestone can map these normalized events into rule coverage and correlation workflows.

This milestone does not provide streaming ingestion, webhook handling, cursor checkpoints, retry queues, alert enrichment, or production secret-manager integration. The Wazuh adapter currently uses a bounded search request and a single local transaction. Deployments requiring continuous collection should add a separately authorized worker with durable checkpoints and the same tenant, rate, audit, and redaction controls rather than weakening this request path.
