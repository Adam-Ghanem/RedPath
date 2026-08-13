# RedPath database schema

The MVP uses SQLite for portability and keeps the schema compatible with PostgreSQL through SQLAlchemy. The database stores normalized evidence rather than raw credentials. Sensitive Wazuh credentials are supplied through environment variables at runtime and are never persisted in RedPath tables.

| Table | Key fields | Purpose |
| --- | --- | --- |
| `scan_runs` | `id`, `mode`, `dry_run`, `targets`, `warnings`, `created_at` | Assessment run metadata and scope context |
| `assets` | `id`, `scan_id`, `ip`, `hostname`, `ports`, `services` | Normalized recon observations |
| `findings` | `id`, `severity`, `asset_id`, `technique_id`, `cvss_score`, `cvss_vector`, `evidence` | Risk-bearing observations and remediation context |
| `graph_nodes` | `id`, `label`, `kind`, `criticality`, `metadata_json` | Attack-path graph vertices |
| `graph_edges` | `source`, `target`, `technique_id`, `weight`, `rationale` | Explainable graph relationships |
| `purple_runs` | `id`, `technique_ids`, `dry_run`, `coverage_percent` | Purple-team comparison metadata |
| `detection_observations` | `purple_run_id`, `technique_id`, `detected`, `evidence_count`, `alert_ids` | Per-technique coverage and gaps |
| `campaigns` | `id`, `name`, `objective`, `owner`, `status`, `scope_snapshot` | Governed assessment case |
| `campaign_run_links` | `campaign_id`, `run_id`, `linked_at` | Assessment runs attached to a case |
| `evidence_items` | `id`, `campaign_id`, `source`, `sha256`, `technique_id`, `review_status` | Provenance metadata and review state |
| `remediation_items` | `id`, `campaign_id`, `finding_title`, `technique_id`, `owner`, `priority`, `status`, `verification_evidence_id` | Evidence-backed remediation action |
| `risk_acceptances` | `id`, `campaign_id`, `remediation_id`, `technique_id`, `approver`, `expires_on`, `status` | Time-bounded governance decision |
| `audit_events` | `id`, `operation`, `actor`, `details`, `digest`, `created_at` | Searchable database copy of the append-only audit chain |
| `campaign_transitions` | `campaign_id`, `from_status`, `to_status`, `actor`, `note`, `created_at` | Append-only case lifecycle history |
| `evidence_review_events` | `evidence_id`, `from_status`, `to_status`, `reviewer`, `notes`, `created_at` | Append-only evidence review history |
| `remediation_transitions` | `remediation_id`, `from_status`, `to_status`, `actor`, `note`, `created_at` | Append-only remediation lifecycle history |

The current API implementation writes the append-only JSONL audit stream directly and prepares the relational schema for the next persistence increment. This split makes the audit path available even if a database migration fails, while still allowing dashboards and reports to query structured history in v1. AI-08 adds additive initialization migration support for the nullable remediation verification reference; the migration does not drop or rewrite existing records.

## Risk fields

The `findings` table stores both a numeric CVSS value and the vector string. That is intentional: FIRST describes CVSS as a framework with Base, Temporal, and Environmental metric groups, and the score should be interpreted together with the vector and local context [1]. RedPath's graph risk score remains a separate prioritization signal based on path weight, centrality, asset criticality, and detection coverage.

## References

[1]: https://www.first.org/cvss/v3.1/specification-document "FIRST CVSS v3.1 specification"
