-- Add only the normalized, allow-listed correlation projection column.
-- This migration never contacts or mutates the remote Wazuh Indexer.

ALTER TABLE telemetry_events
    ADD COLUMN correlation_fields JSON NOT NULL DEFAULT '{}';
