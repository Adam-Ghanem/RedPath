-- AI-03: durable asynchronous safe-discovery jobs.
-- Apply after the existing RedPath schema in deployments that use an external
-- migration runner. Local SQLite bootstrap also creates this table via metadata.
CREATE TABLE IF NOT EXISTS discovery_jobs (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    profile VARCHAR(32) NOT NULL DEFAULT 'safe',
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    dry_run BOOLEAN NOT NULL DEFAULT TRUE,
    targets JSON NOT NULL,
    scan_id VARCHAR(36),
    result_json JSON,
    error TEXT,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS ix_discovery_jobs_tenant_id ON discovery_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS ix_discovery_jobs_status ON discovery_jobs (status);
CREATE INDEX IF NOT EXISTS ix_discovery_jobs_scan_id ON discovery_jobs (scan_id);
