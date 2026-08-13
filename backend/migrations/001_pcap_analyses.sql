-- AI-04: offline PCAP analysis metadata and normalized observations.
-- Raw capture bytes are intentionally not stored by this migration.
CREATE TABLE IF NOT EXISTS pcap_analyses (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    evidence_id VARCHAR(36) NOT NULL REFERENCES evidence_items(id),
    campaign_id VARCHAR(36) NULL REFERENCES campaigns(id),
    file_name VARCHAR(255) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    file_size INTEGER NOT NULL,
    capture_format VARCHAR(16) NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    first_packet_at TIMESTAMP NULL,
    last_packet_at TIMESTAMP NULL,
    protocol_counts JSON NOT NULL,
    endpoints JSON NOT NULL,
    dns_queries JSON NOT NULL,
    observations JSON NOT NULL,
    warnings JSON NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_pcap_analyses_tenant_id ON pcap_analyses (tenant_id);
CREATE INDEX IF NOT EXISTS ix_pcap_analyses_evidence_id ON pcap_analyses (evidence_id);
CREATE INDEX IF NOT EXISTS ix_pcap_analyses_campaign_id ON pcap_analyses (campaign_id);
CREATE INDEX IF NOT EXISTS ix_pcap_analyses_sha256 ON pcap_analyses (sha256);
