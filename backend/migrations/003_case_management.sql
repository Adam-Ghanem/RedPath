-- Case management phase 3: assignment, verification, approval, and custody metadata.
-- Apply after the existing schema migrations. This migration is additive and does not
-- alter external systems or delete existing data.

ALTER TABLE evidence_items ADD COLUMN custody_status VARCHAR(32) NOT NULL DEFAULT 'unverified';
ALTER TABLE evidence_items ADD COLUMN custody_verified_by VARCHAR(128);
ALTER TABLE evidence_items ADD COLUMN custody_verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE evidence_items ADD COLUMN custody_verification_sha256 VARCHAR(64);

ALTER TABLE remediation_items ADD COLUMN assigned_to VARCHAR(128);
ALTER TABLE remediation_items ADD COLUMN verification_status VARCHAR(32) NOT NULL DEFAULT 'unverified';
ALTER TABLE remediation_items ADD COLUMN verified_by VARCHAR(128);
ALTER TABLE remediation_items ADD COLUMN verified_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE risk_acceptances ADD COLUMN approval_status VARCHAR(32) NOT NULL DEFAULT 'approved';
ALTER TABLE risk_acceptances ADD COLUMN approved_by VARCHAR(128);
ALTER TABLE risk_acceptances ADD COLUMN approved_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE risk_acceptances ADD COLUMN revoked_by VARCHAR(128);
ALTER TABLE risk_acceptances ADD COLUMN revoked_at TIMESTAMP WITH TIME ZONE;

CREATE TABLE IF NOT EXISTS evidence_custody_events (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    case_id VARCHAR(36) NOT NULL,
    evidence_id VARCHAR(36) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    manifest_sha256 VARCHAR(64) NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_evidence_items_custody_status ON evidence_items (custody_status);
CREATE INDEX IF NOT EXISTS ix_remediation_items_assigned_to ON remediation_items (assigned_to);
CREATE INDEX IF NOT EXISTS ix_remediation_items_verification_status ON remediation_items (verification_status);
CREATE INDEX IF NOT EXISTS ix_risk_acceptances_approval_status ON risk_acceptances (approval_status);
CREATE INDEX IF NOT EXISTS ix_evidence_custody_events_tenant_id ON evidence_custody_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_evidence_custody_events_case_id ON evidence_custody_events (case_id);
CREATE INDEX IF NOT EXISTS ix_evidence_custody_events_evidence_id ON evidence_custody_events (evidence_id);

-- Rollback note: do not run destructive rollback in production. To roll back application
-- behavior safely, deploy the previous application version and leave these nullable/
-- defaulted columns and the append-only custody table in place. If a maintenance window
-- later requires physical removal, take a verified backup, confirm no newer application
-- depends on the fields, and remove only these phase-3 columns/table through a separately
-- reviewed migration with explicit approval.
