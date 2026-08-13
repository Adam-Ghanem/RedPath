-- AI-08 phase 2: tenant-scoped case governance history and immutable evidence metadata.
-- Apply after the existing tenant migration. No external systems are modified.

ALTER TABLE evidence_items ADD COLUMN manifest_sha256 VARCHAR(64);

CREATE TABLE IF NOT EXISTS case_governance_events (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    case_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    summary TEXT NOT NULL,
    metadata_json JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_case_governance_events_tenant_id ON case_governance_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_case_governance_events_case_id ON case_governance_events (case_id);
CREATE INDEX IF NOT EXISTS ix_case_governance_events_event_type ON case_governance_events (event_type);
CREATE INDEX IF NOT EXISTS ix_evidence_items_manifest_sha256 ON evidence_items (manifest_sha256);
