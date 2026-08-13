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
    discovery_api_token: str = ""
    discovery_tenant_id: str = "lab"
    audit_log_path: str = "./data/audit.jsonl"
    wazuh_indexer_url: str = "https://wazuh-indexer.local:9200"
    wazuh_verify_tls: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_cidr_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_cidrs.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
