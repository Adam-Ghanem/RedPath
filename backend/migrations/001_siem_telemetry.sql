-- AI-05: read-only SIEM/Wazuh telemetry ingestion
-- Apply once after the existing schema. The application also keeps metadata.create_all
-- for the prototype's fresh SQLite environments; production deployments should apply
-- migrations through the release process.

CREATE TABLE IF NOT EXISTS telemetry_ingestion_runs (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    source VARCHAR(32) NOT NULL DEFAULT 'wazuh',
    start_at TIMESTAMP WITH TIME ZONE NOT NULL,
    end_at TIMESTAMP WITH TIME ZONE NOT NULL,
    fetched_count INTEGER NOT NULL DEFAULT 0,
    stored_count INTEGER NOT NULL DEFAULT 0,
    deduplicated_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_telemetry_ingestion_runs_tenant_id
    ON telemetry_ingestion_runs (tenant_id);

CREATE TABLE IF NOT EXISTS telemetry_events (
    id VARCHAR(128) PRIMARY KEY,
    ingestion_run_id VARCHAR(36) NOT NULL REFERENCES telemetry_ingestion_runs(id),
    tenant_id VARCHAR(128) NOT NULL,
    source VARCHAR(32) NOT NULL DEFAULT 'wazuh',
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    severity VARCHAR(16) NOT NULL,
    rule_id VARCHAR(64),
    rule_description VARCHAR(1000),
    asset_id VARCHAR(128),
    technique_ids JSON NOT NULL,
    summary VARCHAR(1000) NOT NULL DEFAULT '',
    safe_fields JSON NOT NULL,
    raw_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_telemetry_events_tenant_id ON telemetry_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_telemetry_events_observed_at ON telemetry_events (observed_at);
CREATE INDEX IF NOT EXISTS ix_telemetry_events_rule_id ON telemetry_events (rule_id);
CREATE INDEX IF NOT EXISTS ix_telemetry_events_asset_id ON telemetry_events (asset_id);
CREATE INDEX IF NOT EXISTS ix_telemetry_events_raw_sha256 ON telemetry_events (raw_sha256);
