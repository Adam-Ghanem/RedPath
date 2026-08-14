from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.scope import ScopePolicy
from app.schemas.contracts import AssetObservation, ReconResult
from app.services.recon import ReconService


class AuthorizationError(ValueError):
    """Raised when an operator attempts to run outside the approved CLI contract."""


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_SAFE_WEB_PATHS = ("/", "/robots.txt", "/.well-known/security.txt", "/health", "/login", "/api")


@dataclass(frozen=True)
class AuthorizedScope:
    scope_id: str
    allowed_cidrs: tuple[str, ...]
    allowed_web_origins: tuple[str, ...] = ()
    max_targets: int = 1
    max_web_paths: int = 6

    @classmethod
    def from_file(cls, path: Path) -> "AuthorizedScope":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise AuthorizationError("scope file must contain a JSON object")
        scope_id = raw.get("scope_id")
        cidrs = raw.get("allowed_cidrs")
        origins = raw.get("allowed_web_origins", [])
        if not isinstance(scope_id, str) or not _IDENTIFIER.fullmatch(scope_id):
            raise AuthorizationError("scope_id must be an 8-128 character authorization identifier")
        if not isinstance(cidrs, list) or not all(isinstance(item, str) for item in cidrs):
            raise AuthorizationError("allowed_cidrs must be a non-empty list of CIDR strings")
        ScopePolicy.from_strings(cidrs)
        if not isinstance(origins, list) or not all(isinstance(item, str) for item in origins):
            raise AuthorizationError("allowed_web_origins must be a list of HTTP(S) origins")
        normalized_origins = tuple(_normalize_origin(origin) for origin in origins)
        max_targets = raw.get("max_targets", 1)
        max_web_paths = raw.get("max_web_paths", len(_SAFE_WEB_PATHS))
        if not isinstance(max_targets, int) or not 1 <= max_targets <= 16:
            raise AuthorizationError("max_targets must be between 1 and 16")
        if not isinstance(max_web_paths, int) or not 1 <= max_web_paths <= len(_SAFE_WEB_PATHS):
            raise AuthorizationError(f"max_web_paths must be between 1 and {len(_SAFE_WEB_PATHS)}")
        return cls(
            scope_id=scope_id,
            allowed_cidrs=tuple(cidrs),
            allowed_web_origins=normalized_origins,
            max_targets=max_targets,
            max_web_paths=max_web_paths,
        )

    @property
    def policy(self) -> ScopePolicy:
        return ScopePolicy.from_strings(list(self.allowed_cidrs))

    def validate_target(self, target: str) -> str:
        return self.policy.validate_ip(target)

    def validate_web_origin(self, value: str) -> str:
        origin = _normalize_origin(value)
        if origin not in self.allowed_web_origins:
            raise AuthorizationError("web base URL is outside the approved scope origins")
        return origin


@dataclass(frozen=True)
class CandidateVulnerability:
    candidate_id: str
    asset_ip: str
    service: str
    severity: str
    title: str
    rationale: str
    remediation: str
    requires_validation: bool = True


@dataclass(frozen=True)
class WebObservation:
    url: str
    status_code: int
    content_length: int | None


@dataclass
class AuthorizedScanReport:
    scan_id: str
    scope_id: str
    authorization_id: str
    operator: str
    target: str
    profile: str
    dry_run: bool
    created_at: str
    recon: ReconResult
    candidates: list[CandidateVulnerability] = field(default_factory=list)
    web_observations: list[WebObservation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["recon"] = self.recon.model_dump(mode="json")
        return data


class AuthorizedScanService:
    """Scope-bound reconnaissance only; no exploitation, credential attacks, or evasive behavior."""

    def __init__(self, scope: AuthorizedScope, *, timeout_seconds: int = 30) -> None:
        self.scope = scope
        self.recon = ReconService(scope.policy, timeout_seconds=timeout_seconds)

    def run(
        self,
        target: str,
        *,
        authorization_id: str,
        operator: str,
        execute: bool = False,
        profile: str = "service_inventory",
        web_base_url: str | None = None,
        audit_file: Path,
    ) -> AuthorizedScanReport:
        if not _IDENTIFIER.fullmatch(authorization_id):
            raise AuthorizationError("authorization_id must be an 8-128 character identifier")
        if not _IDENTIFIER.fullmatch(operator):
            raise AuthorizationError("operator must be an 8-128 character identifier")
        if profile not in {"safe", "service_inventory"}:
            raise AuthorizationError("only safe and service_inventory profiles are permitted")
        validated_target = self.scope.validate_target(target)
        origin = self.scope.validate_web_origin(web_base_url) if web_base_url else None
        scan_id = str(uuid.uuid4())
        recon = self.recon.run([validated_target], profile=profile, dry_run=not execute, scan_id=scan_id)
        candidates = _correlate_candidates(recon.assets)
        warnings = list(recon.warnings)
        observations: list[WebObservation] = []
        if origin and execute:
            observations, web_warnings = self._enumerate_web(origin)
            warnings.extend(web_warnings)
        elif origin:
            warnings.append("Dry-run enabled: no web requests were made.")
        report = AuthorizedScanReport(
            scan_id=scan_id,
            scope_id=self.scope.scope_id,
            authorization_id=authorization_id,
            operator=operator,
            target=validated_target,
            profile=profile,
            dry_run=not execute,
            created_at=datetime.now(UTC).isoformat(),
            recon=recon,
            candidates=candidates,
            web_observations=observations,
            warnings=warnings,
        )
        _append_audit(audit_file, report)
        return report

    def _enumerate_web(self, origin: str) -> tuple[list[WebObservation], list[str]]:
        observations: list[WebObservation] = []
        warnings: list[str] = []
        headers = {"User-Agent": "RedPath-Authorized-Inventory/1.0"}
        try:
            with httpx.Client(timeout=5.0, follow_redirects=False, headers=headers) as client:
                for path in _SAFE_WEB_PATHS[: self.scope.max_web_paths]:
                    response = client.get(f"{origin}{path}")
                    if 200 <= response.status_code < 400:
                        content_length = response.headers.get("content-length")
                        observations.append(
                            WebObservation(
                                url=f"{origin}{path}",
                                status_code=response.status_code,
                                content_length=(
                                    int(content_length)
                                    if content_length and content_length.isdigit()
                                    else None
                                ),
                            )
                        )
        except httpx.HTTPError as exc:
            warnings.append(f"Approved web inventory could not complete: {type(exc).__name__}")
        return observations, warnings


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
        raise AuthorizationError("web scope must be an absolute HTTP(S) origin without a path")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AuthorizationError("web scope must not contain credentials, query, or fragment")
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _correlate_candidates(assets: list[AssetObservation]) -> list[CandidateVulnerability]:
    catalog = {
        "http": (
            "medium",
            "HTTP service requires patch validation",
            "Verify software version and apply vendor patches.",
        ),
        "https": (
            "medium",
            "HTTPS service requires TLS and patch validation",
            "Review TLS posture and apply vendor patches.",
        ),
        "ssh": (
            "medium",
            "SSH service requires configuration validation",
            "Verify patch level, MFA, and approved access controls.",
        ),
        "smb": (
            "high",
            "SMB service requires patch and signing validation",
            "Verify patch level and SMB signing policy.",
        ),
        "microsoft-ds": (
            "high",
            "SMB service requires patch and signing validation",
            "Verify patch level and SMB signing policy.",
        ),
        "rdp": (
            "high",
            "RDP service requires exposure validation",
            "Restrict exposure and verify patch level and MFA controls.",
        ),
    }
    candidates: list[CandidateVulnerability] = []
    for asset in assets:
        for service in sorted(set(asset.services)):
            item = catalog.get(service.lower())
            if not item:
                continue
            severity, title, remediation = item
            candidates.append(
                CandidateVulnerability(
                    candidate_id=f"candidate-{asset.ip}-{service}".replace("/", "-"),
                    asset_ip=asset.ip,
                    service=service,
                    severity=severity,
                    title=title,
                    rationale=(
                        "Candidate correlation from an authorized inventory scan; validation is required "
                        "before treating it as a vulnerability."
                    ),
                    remediation=remediation,
                )
            )
    return candidates


def _append_audit(path: Path, report: AuthorizedScanReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "event": "authorized_scan.completed",
        "scan_id": report.scan_id,
        "scope_id": report.scope_id,
        "authorization_id": report.authorization_id,
        "operator": report.operator,
        "target": report.target,
        "profile": report.profile,
        "dry_run": report.dry_run,
        "created_at": report.created_at,
        "asset_count": len(report.recon.assets),
        "candidate_count": len(report.candidates),
        "web_observation_count": len(report.web_observations),
        "warnings": report.warnings,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    path.chmod(0o600)
