from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "RedPath"
    environment: str = "lab"
    database_url: str = "sqlite:///./data/redpath.db"
    allowed_cidrs: str = "192.168.56.0/24,10.10.10.0/24"
    dry_run: bool = True
    recon_timeout_seconds: int = 30
    recon_max_workers: int = 2
    discovery_max_jobs_per_minute: int = 30
    discovery_job_retention_hours: int = 24
    discovery_job_retention_max: int = 500
    discovery_api_token: str = ""
    discovery_tenant_id: str = "lab"
    audit_log_path: str = "./data/audit.jsonl"
    wazuh_indexer_url: str = "https://wazuh-indexer.local:9200"
    wazuh_username: str = ""
    wazuh_password: str = ""
    wazuh_verify_tls: bool = True
    log_level: str = "INFO"
    metrics_enabled: bool = True
    release: str = "dev"
    auth_bootstrap_token: str = ""
    rate_limit_requests_per_minute: int = 120
    ai_features_enabled: bool = False
    ai_provider: str = "openai_compatible"
    ai_model: str = "gpt-5-mini"
    ai_api_key: str = ""
    ai_api_base: str = ""
    ai_request_timeout_seconds: int = 8
    ai_copilot_requests_per_minute: int = 10
    ai_cache_ttl_seconds: int = 300
    ai_cache_max_entries: int = 256
    ai_max_context_chars: int = 4000
    pcap_max_upload_bytes: int = 50 * 1024 * 1024
    pcap_max_packets: int = 100_000
    pcap_max_endpoints: int = 100
    pcap_max_dns_queries: int = 500
    pcap_max_flows: int = 1_000
    pcap_max_observations: int = 1_000
    pcap_redaction_salt: str = "redpath-lab-redaction-salt"
    siem_max_query_window_hours: int = 24
    siem_request_timeout_seconds: int = 20

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_cidr_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_cidrs.split(",") if item.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
