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

Apply `backend/migrations/003_telemetry_resilience.sql` after the existing telemetry migrations. The migration is additive and creates `telemetry_ingestion_state` and `telemetry_dead_letters` with tenant/source and expiration indexes. The application migration runner records schema version 5 when both tables exist.

Rollback is application-safe: deploying the previous application version leaves these additive tables in place and ignores them. Do not drop the tables during a routine rollback because they contain operational recovery history. If removal is required by a separately approved data-retention process, export only approved aggregate audit information first, then remove the tables in a maintenance window; no remote Wazuh operation is part of rollback.

## Integration boundary

The worker owns checkpoint advancement, retry scheduling, and retention-hook invocation. API routes expose authenticated, tenant-scoped health diagnostics and existing read-only telemetry workflows. Server-derived principal identity, RBAC, audit integrity, redaction, and dry-run controls remain authoritative. No endpoint accepts a tenant override, arbitrary connector URL, raw query JSON, or remote mutation request.
