# Telemetry connector resilience

RedPath’s telemetry connector is a **read-only** Wazuh Indexer adapter. It is restricted to the HTTPS `wazuh-alerts*` search path, uses the server-side `redpath_reader` role, requires TLS verification, and never sends agent-control, active-response, update, delete, or configuration requests to the remote SIEM.

## Recovery and checkpoints

The adapter emits an opaque, bounded cursor containing only a version, UTC observed timestamp, provider identifier, and expected schema version. The cursor is used as OpenSearch `search_after` state for deterministic page recovery. Cursor values are validated for version, timestamp, provider identifier, and maximum size before they reach a remote query. Invalid cursors fail closed and create only bounded local dead-letter metadata.

Checkpoint state is tenant- and source-scoped. A successful local run records the cursor, schema version, last observed event time, lag value, and resets the consecutive-failure count. Replaying a recovered page remains subject to the existing tenant-scoped event fingerprint and deduplication behavior.

## Safe failure and dead letters

Failures are represented by a small allow-list of error codes: `connector_error`, `schema_drift`, `checkpoint_invalid`, and `persistence_error`. Dead-letter records retain no raw Wazuh documents, exception text, credentials, request bodies, headers, or query parameters. Metadata is bounded by `SIEM_DEAD_LETTER_METADATA_MAX_BYTES`, retry time uses capped exponential backoff, and records expire after `SIEM_DEAD_LETTER_RETENTION_HOURS`.

The retention hook prunes expired dead-letter metadata by tenant when invoked by the worker. It never deletes canonical telemetry events or modifies remote SIEM state. The maximum number of rows pruned per call is bounded by `SIEM_DEAD_LETTER_RETENTION_MAX`.

## Schema drift and health

Incoming documents are checked against the current `wazuh-alert-v1` shape before normalization. The drift detector records a short schema signature and fails closed when the required rule object is absent or the payload is not an object. It does not persist the provider document. The health response exposes only tenant-scoped status, lag seconds, checkpoint presence, schema version, drift count, consecutive failures, dead-letter count, and safe error code.

The metrics registry uses fixed, label-free telemetry names for ingestion attempts/success/failure, checkpoint recovery, schema drift, dead letters, correlation evaluations/matches, retention pruning, lag, consecutive failures, and dead-letter count. Tenant IDs, rule IDs, event IDs, cursors, and payload values are not metric labels.

## Configuration

| Setting | Default | Safety purpose |
| --- | --- | --- |
| `SIEM_CONNECTOR_ROLE` | `redpath_reader` | Rejects elevated or unknown connector roles. |
| `SIEM_CONNECTOR_READ_ONLY` | `true` | Rejects mutation-capable connector configuration. |
| `SIEM_CHECKPOINT_MAX_BYTES` | `1024` | Bounds opaque recovery state. |
| `SIEM_DEAD_LETTER_RETENTION_HOURS` | `72` | Limits local failure metadata lifetime. |
| `SIEM_DEAD_LETTER_METADATA_MAX_BYTES` | `2048` | Prevents raw or oversized failure payloads. |
| `SIEM_DEAD_LETTER_RETENTION_MAX` | `1000` | Bounds one retention operation. |
| `SIEM_LAG_WARNING_SECONDS` | `900` | Defines the source-lag diagnostic threshold. |
| `SIEM_SCHEMA_VERSION` | `wazuh-alert-v1` | Identifies the expected normalized provider shape. |

All sensitive connector credentials remain deployment secrets and are never persisted in RedPath tables or emitted in diagnostics.

## Migration and rollback

Apply Alembic revision `6f4a2b8c9d10` after head `22d614b2aac8`. The revision additively extends `telemetry_ingestion_state` with source circuit, capacity-window, and last-attempt fields.

Rollback is application-safe: downgrading to `22d614b2aac8` removes only those operational columns and leaves canonical telemetry, dead-letter metadata, and prior checkpoint tables intact. Do not drop the tables during a routine rollback because they contain operational recovery history. No remote Wazuh operation is part of migration or rollback.

## Integration boundary

The worker owns checkpoint advancement, retry scheduling, and retention-hook invocation. API routes expose authenticated, tenant-scoped health diagnostics and existing read-only telemetry workflows. Server-derived principal identity, RBAC, audit integrity, redaction, and dry-run controls remain authoritative. No endpoint accepts a tenant override, arbitrary connector URL, raw query JSON, or remote mutation request.

## Multi-source operational resilience

Recovery state is isolated by the authenticated tenant and a bounded source identifier. A source circuit opens after the configured consecutive-failure threshold, rejects additional work during the cooldown, and permits one half-open recovery attempt after the cooldown. A successful local run closes only that source circuit; it does not affect another source or tenant.

Each source has a rolling event and estimated-byte capacity window. Requests that exceed the remaining local budget fail closed before any connector call. The default limits are 1,000 estimated events and 4,000,000 estimated bytes per 60-second window. These are admission-control estimates, not measurements of remote data, and they never cause a remote source mutation.

## Freshness SLO and correlation fan-in

Health diagnostics report lag seconds, a configured freshness target, and whether the latest observed event meets that target. Historical fixture timestamps may report an SLO miss while the connector remains operationally healthy; explicit source failures, open circuits, or schema drift are the safe-failure conditions that mark the source degraded. Freshness breaches are counted through fixed-name metrics without tenant or source labels.

Detection correlation is bounded to 500 normalized events by default, even when a caller requests a larger read window. The response declares the effective fan-in limit and whether truncation occurred. This prevents a single tenant query from consuming unbounded evaluator memory or CPU. Case evidence remains a minimum safe projection and never includes raw provider payloads.

## Schema-drift remediation

When a required provider object is missing or has an incompatible shape, ingestion fails closed before normalization and stores only a bounded schema signature and safe error code. The health response exposes the remediation guidance `review_provider_schema_contract`. Operators should compare the provider mapping to the expected version, update the adapter’s allow-list in a reviewed change, replay a sanitized fixture, and only then resume the affected source. No raw provider document is retained as part of drift handling.

## Migration and downgrade

The Alembic revision `6f4a2b8c9d10` adds circuit, capacity-window, and last-attempt columns to `telemetry_ingestion_state`. Its downgrade removes only those operational columns. It does not drop canonical telemetry events, dead-letter records, or the existing checkpoint tables. A rollback therefore preserves evidence and recovery history while older application code ignores the additional columns. Apply and downgrade only through the repository’s Alembic chain.

Replay-safe fixture tests cover source isolation, circuit cooldown, capacity rejection, freshness SLO calculation, bounded fan-in, schema-drift guidance, and upgrade/downgrade behavior. The fixtures do not contact live SIEM infrastructure and no connector exposes write-capable operations.
