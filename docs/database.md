# RedPath database schema

The MVP uses SQLite for portability and keeps the schema compatible with PostgreSQL through SQLAlchemy. The database stores normalized evidence rather than raw credentials. Sensitive Wazuh credentials are supplied through environment variables at runtime and are never persisted in RedPath tables.

| Table | Key fields | Purpose |
| --- | --- | --- |
| `scan_runs` | `id`, `tenant_id`, `mode`, `dry_run`, `targets`, `warnings`, `created_at` | Tenant-scoped assessment and discovery run metadata |
| `discovery_jobs` | `id`, `tenant_id`, `actor`, `profile`, `status`, `dry_run`, `targets`, `scan_id`, `expires_at`, timestamps | Protected asynchronous job lifecycle with bounded retention; actor is captured from the authenticated principal |
| `assets` | `id`, `tenant_id`, `scan_id`, `ip`, `hostname`, `ports`, `services`, `provenance_json`, `observation_hash`, `first_seen_at`, `last_seen_at` | Idempotently reconciled normalized observations conforming to the shared asset identity contract |
| `findings` | `id`, `severity`, `asset_id`, `technique_id`, `cvss_score`, `cvss_vector`, `evidence` | Risk-bearing observations and remediation context |
| `graph_nodes` | `id`, `label`, `kind`, `criticality`, `metadata_json` | Attack-path graph vertices |
| `graph_edges` | `source`, `target`, `technique_id`, `weight`, `rationale` | Explainable graph relationships |
| `purple_runs` | `id`, `technique_ids`, `dry_run`, `coverage_percent` | Purple-team comparison metadata |
| `detection_observations` | `purple_run_id`, `technique_id`, `detected`, `evidence_count`, `alert_ids` | Per-technique coverage and gaps |
| `audit_events` | `id`, `operation`, `actor`, `details`, `digest`, `created_at` | Searchable database copy of the append-only audit chain |
| `telemetry_ingestion_runs` | `id`, `tenant_id`, `start_at`, `end_at`, fetched/stored/deduplicated counters | Tenant-scoped local ingestion run metadata |
| `telemetry_events` | `id`, `tenant_id`, `observed_at`, `technique_ids`, `safe_fields`, `correlation_fields`, `raw_sha256` | Redacted normalized Wazuh telemetry; no raw provider payload |
| `telemetry_ingestion_state` | `tenant_id`, `source`, `checkpoint_cursor`, schema/failure/lag fields | Tenant/source checkpoint recovery and safe health state |
| `telemetry_dead_letters` | `tenant_id`, `source`, `error_code`, bounded metadata, retry/expiry timestamps | Expiring local failure metadata; no raw provider payload |

The current API implementation writes the append-only JSONL audit stream directly and uses additive migrations for discovery job expiry, authenticated actor capture, asset provenance, observation hashes, first/last-seen timestamps, telemetry ingestion, and correlation records. Job retention is per tenant and removes only expired or over-capacity terminal job metadata; normalized assets and audit records are retained for evidence continuity. Fresh local SQLite environments receive compatible columns through SQLAlchemy metadata creation. For upgraded deployments, apply `backend/migrations/001_siem_telemetry.sql`, `backend/migrations/002_telemetry_correlation.sql`, and `backend/migrations/003_telemetry_resilience.sql` through the release process before relying on telemetry resilience state. The resilience migration is additive; rollback deploys the previous application while retaining these tables for safe operational history.

## Risk fields

The `findings` table stores both a numeric CVSS value and the vector string. That is intentional: FIRST describes CVSS as a framework with Base, Temporal, and Environmental metric groups, and the score should be interpreted together with the vector and local context [1]. RedPath's graph risk score remains a separate prioritization signal based on path weight, centrality, asset criticality, and detection coverage.

## References

[1]: https://www.first.org/cvss/v3.1/specification-document "FIRST CVSS v3.1 specification"
