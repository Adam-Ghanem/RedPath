-- Additive inventory job observability fields.
-- Apply after the existing discovery inventory reconciliation migration.
ALTER TABLE discovery_jobs ADD COLUMN duration_ms INTEGER;
ALTER TABLE discovery_jobs ADD COLUMN recovery_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE discovery_jobs ADD COLUMN recovered_at TIMESTAMP WITH TIME ZONE;

-- Rollback: before deployment, remove these three columns with the target database's
-- supported reversible column-removal operation. No data tables or asset rows are removed.
