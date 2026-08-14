from functools import lru_cache
from typing import Literal

from pydantic import model_validator
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
    discovery_recovery_timeout_seconds: int = 300
    discovery_lease_seconds: int = 60
    discovery_retry_budget: int = 2
    discovery_checkpoint_max_bytes: int = 2048
    discovery_result_max_bytes: int = 8192
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
    auth_provider: Literal["opaque", "oidc"] = "opaque"
    oidc_issuer_url: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    auth_mfa_required_permissions: str = ""
    auth_session_ttl_minutes: int = 15
    service_account_token_ttl_minutes: int = 60
    service_account_max_ttl_days: int = 90
    auth_token_rotation_overlap_seconds: int = 30
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
    risk_simulation_cache_ttl_seconds: int = 30
    risk_simulation_cache_max_entries: int = 256
    risk_simulation_max_paths: int = 500
    risk_simulation_max_traversal_steps: int = 100_000
    pcap_max_upload_bytes: int = 50 * 1024 * 1024
    pcap_max_packets: int = 100_000
    pcap_max_endpoints: int = 100
    pcap_max_dns_queries: int = 500
    pcap_max_flows: int = 1_000
    pcap_max_observations: int = 1_000
    pcap_redaction_salt: str = "redpath-lab-redaction-salt"
    pcap_retention_days: int = 90
    pcap_quarantine_retention_days: int = 30
    pcap_deletion_grace_days: int = 7
    pcap_drilldown_max_flows: int = 25
    pcap_drilldown_max_dns: int = 25
    pcap_drilldown_max_observations: int = 100
    siem_max_query_window_hours: int = 24
    siem_request_timeout_seconds: int = 20
    siem_connector_role: str = "redpath_reader"
    siem_connector_read_only: bool = True
    siem_checkpoint_max_bytes: int = 1024
    siem_dead_letter_retention_hours: int = 72
    siem_dead_letter_metadata_max_bytes: int = 2048
    siem_dead_letter_retention_max: int = 1000
    siem_lag_warning_seconds: int = 900
    siem_schema_version: str = "wazuh-alert-v1"
    siem_circuit_failure_threshold: int = 3
    siem_circuit_cooldown_seconds: int = 300
    siem_capacity_window_seconds: int = 60
    siem_capacity_max_events: int = 1000
    siem_capacity_max_bytes: int = 4_000_000
    siem_freshness_slo_target_seconds: int = 900
    siem_correlation_max_fan_in: int = 500

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def validate_identity_settings(self) -> "Settings":
        if self.auth_provider == "oidc" and not all(
            (self.oidc_issuer_url, self.oidc_audience, self.oidc_jwks_url)
        ):
            raise ValueError("OIDC provider requires issuer, audience, and JWKS URL")
        if self.auth_session_ttl_minutes < 5 or self.auth_session_ttl_minutes > 1440:
            raise ValueError("auth session TTL must be between 5 and 1440 minutes")
        if self.service_account_token_ttl_minutes < 5:
            raise ValueError("service-account token TTL must be at least 5 minutes")
        if self.service_account_max_ttl_days < 1 or self.service_account_max_ttl_days > 365:
            raise ValueError("service-account maximum TTL must be between 1 and 365 days")
        if self.auth_token_rotation_overlap_seconds < 0 or self.auth_token_rotation_overlap_seconds > 3600:
            raise ValueError("token rotation overlap must be between 0 and 3600 seconds")
        return self

    @property
    def auth_mfa_required_permission_list(self) -> frozenset[str]:
        return frozenset(
            item.strip() for item in self.auth_mfa_required_permissions.split(",") if item.strip()
        )

    @property
    def allowed_cidr_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_cidrs.split(",") if item.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
