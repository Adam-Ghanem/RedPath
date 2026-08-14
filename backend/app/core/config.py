import warnings
from functools import lru_cache
from typing import Literal

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
    pcap_max_packets: int = 100_000
    pcap_max_endpoints: int = 100
    pcap_max_dns_queries: int = 500
    pcap_max_flows: int = 1_000
    pcap_max_observations: int = 1_000
    pcap_redaction_salt: str = "redpath-lab-redaction-salt"
    siem_max_query_window_hours: int = 24
    siem_request_timeout_seconds: int = 20
    ai_features_enabled: bool = False
    ai_provider: Literal["none", "local", "anthropic"] = "none"
    anthropic_api_key: str = ""
    anthropic_api_url: str = "https://api.anthropic.com/v1/messages"
    # Deprecated compatibility field; use anthropic_model_fast/deep instead.
    anthropic_model: str = "claude-haiku-4-5"
    anthropic_model_fast: str = "claude-haiku-4-5"
    # Live catalog verified 2026-08-14 exposes claude-sonnet-4-6, not claude-sonnet-5.
    anthropic_model_deep: str = "claude-sonnet-4-6"
    local_llm_base_url: str = "http://127.0.0.1:11434/api/generate"
    local_llm_model: str = "llama3.1:8b"
    local_llm_timeout_seconds: float = 30.0
    anthropic_timeout_seconds: float = 15.0
    anthropic_timeout_seconds_fast: float = 15.0
    anthropic_timeout_seconds_deep: float = 30.0
    anthropic_max_tokens: int = 1200
    anthropic_max_tokens_fast: int = 1200
    anthropic_max_tokens_deep: int = 2400
    ai_cache_ttl_seconds: int = 3600
    ai_cache_max_entries: int = 2000
    ai_requests_per_minute: int = 20
    ai_deep_requests_per_minute: int = 5
    ai_audit_log_path: str = "./data/ai_audit.jsonl"
    ai_audit_retention_days: int = 365
    ai_audit_max_entries: int = 10_000

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def model_for_tier(self, tier: Literal["fast", "deep"]) -> str:
        if "anthropic_model" in self.model_fields_set and "anthropic_model_fast" not in self.model_fields_set:
            warnings.warn(
                "ANTHROPIC_MODEL is deprecated; use ANTHROPIC_MODEL_FAST or ANTHROPIC_MODEL_DEEP",
                DeprecationWarning,
                stacklevel=2,
            )
            return self.anthropic_model
        return self.anthropic_model_fast if tier == "fast" else self.anthropic_model_deep

    def timeout_for_tier(self, tier: Literal["fast", "deep"]) -> float:
        if tier == "fast":
            return self.anthropic_timeout_seconds_fast
        return self.anthropic_timeout_seconds_deep

    def max_tokens_for_tier(self, tier: Literal["fast", "deep"]) -> int:
        if tier == "fast":
            return self.anthropic_max_tokens_fast
        return self.anthropic_max_tokens_deep

    @property
    def allowed_cidr_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_cidrs.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
