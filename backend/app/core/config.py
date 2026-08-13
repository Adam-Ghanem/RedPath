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
    pcap_max_upload_bytes: int = 50 * 1024 * 1024
    siem_max_query_window_hours: int = 24
    siem_request_timeout_seconds: int = 20

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_cidr_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_cidrs.split(",") if item.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
