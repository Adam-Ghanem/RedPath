"""Validate RedPath environment configuration without printing secret values."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.core.config import Settings  # noqa: E402


def validate(settings: Settings, profile: str) -> None:
    if settings.auth_session_ttl_minutes < 5 or settings.auth_session_ttl_minutes > 1440:
        raise RuntimeError("auth session TTL is outside the supported bound")
    if settings.service_account_token_ttl_minutes < 5:
        raise RuntimeError("service-account token TTL is below the supported minimum")
    if settings.rate_limit_requests_per_minute < 1 or settings.rate_limit_requests_per_minute > 10_000:
        raise RuntimeError("rate-limit setting is outside the supported bound")
    if settings.recon_timeout_seconds < 1 or settings.recon_timeout_seconds > 900:
        raise RuntimeError("recon timeout is outside the supported bound")
    if settings.recon_max_workers < 1 or settings.recon_max_workers > 32:
        raise RuntimeError("recon worker count is outside the supported bound")
    if not settings.siem_connector_read_only:
        raise RuntimeError("SIEM connector must remain read-only")
    if not settings.wazuh_verify_tls:
        raise RuntimeError("Wazuh TLS verification must remain enabled")

    if profile == "lab":
        if settings.environment not in {"lab", "dev", "test"}:
            raise RuntimeError("lab profile requires a non-production environment name")
        if not settings.dry_run:
            raise RuntimeError("lab profile must preserve dry-run mode")
        if settings.auth_provider not in {"opaque", "oidc"}:
            raise RuntimeError("lab profile has an unsupported authentication provider")
        return

    if settings.environment not in {"prod", "production"}:
        raise RuntimeError("production profile requires a production environment name")
    if settings.auth_provider != "oidc":
        raise RuntimeError("production profile requires OIDC authentication")
    if not settings.auth_mfa_required_permission_list:
        raise RuntimeError("production profile requires MFA-protected permissions")
    if settings.database_url.startswith("sqlite:"):
        raise RuntimeError("production profile must not use SQLite persistence")
    if not settings.oidc_issuer_url or not settings.oidc_audience or not settings.oidc_jwks_url:
        raise RuntimeError("production profile requires complete OIDC metadata")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("lab", "production"), default="lab")
    args = parser.parse_args()
    try:
        settings = Settings()
        validate(settings, args.profile)
    except Exception as exc:  # pragma: no cover - CLI failure path is asserted by exit code
        print(f"Environment check failed safely: {exc}", file=sys.stderr)
        return 1
    print(f"Environment check passed for {args.profile} profile; secret values were not emitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
