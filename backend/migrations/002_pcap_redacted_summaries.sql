-- RedPath offline PCAP summary hardening.
-- Phase 1 migration remains unchanged; apply this migration after 001_pcap_analyses.sql.
-- Raw packet bytes remain intentionally absent.
ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS redaction_mode VARCHAR(32) NOT NULL DEFAULT 'pseudonymized';
ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS redacted_fields INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS flow_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS flows JSON NOT NULL DEFAULT '[]';
ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS dns_summary JSON NOT NULL DEFAULT '[]';
