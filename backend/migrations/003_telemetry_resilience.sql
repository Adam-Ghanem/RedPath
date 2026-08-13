-- Additive local resilience state only; no remote Wazuh mutation is performed.

CREATE TABLE IF NOT EXISTS telemetry_ingestion_state (
    id VARCHAR(192) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    source VARCHAR(32) NOT NULL DEFAULT 'wazuh',
    checkpoint_cursor TEXT,
    cursor_version VARCHAR(16),
    schema_version VARCHAR(64),
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_event_at TIMESTAMP WITH TIME ZONE,
    last_lag_seconds FLOAT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    schema_drift_count INTEGER NOT NULL DEFAULT 0,
    last_error_code VARCHAR(64),
    last_error_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_telemetry_ingestion_state_tenant_source
    ON telemetry_ingestion_state (tenant_id, source);

CREATE TABLE IF NOT EXISTS telemetry_dead_letters (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    source VARCHAR(32) NOT NULL DEFAULT 'wazuh',
    error_code VARCHAR(64) NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    metadata_json JSON NOT NULL,
    retry_after_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_telemetry_dead_letters_tenant_source
    ON telemetry_dead_letters (tenant_id, source);
CREATE INDEX IF NOT EXISTS ix_telemetry_dead_letters_expires_at
    ON telemetry_dead_letters (expires_at);
