-- Additive discovery inventory reconciliation and retention fields.
-- Apply after the existing discovery job and asset schema.
ALTER TABLE discovery_jobs ADD COLUMN actor VARCHAR(128) NOT NULL DEFAULT 'system';
ALTER TABLE discovery_jobs ADD COLUMN expires_at TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS ix_discovery_jobs_expires_at ON discovery_jobs (expires_at);

ALTER TABLE assets ADD COLUMN provenance_json JSON NOT NULL DEFAULT '{}';
ALTER TABLE assets ADD COLUMN observation_hash VARCHAR(64);
ALTER TABLE assets ADD COLUMN first_seen_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE assets ADD COLUMN last_seen_at TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS ix_assets_observation_hash ON assets (observation_hash);
CREATE INDEX IF NOT EXISTS ix_assets_last_seen_at ON assets (last_seen_at);
