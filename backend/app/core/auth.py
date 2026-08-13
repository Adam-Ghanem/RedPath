from __future__ import annotations

from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import datetime, timezone
from threading import Lock
from time import monotonic
from typing import Callable, Protocol

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.audit import AuditLogger
from app.core.errors import route_template
from app.core.request_context import Principal, reset_principal, set_principal
from app.services.identity import IdentityError, IdentityService
from app.services.service_accounts import ServiceAccountError, ServiceAccountService

BEARER = HTTPBearer(auto_error=False)


class IdentityProviderUnavailable(IdentityError):
    """Raised when an external identity verifier is not configured or available."""


class AuthenticationProvider(Protocol):
    """Stable authentication boundary for opaque sessions and external OIDC adapters."""

    def resolve(self, raw_token: str) -> Principal:
        """Validate a bearer credential and return a server-derived principal."""


class OpaqueSessionProvider:
    def __init__(self, identity: IdentityService) -> None:
        self.identity = identity

    def resolve(self, raw_token: str) -> Principal:
        return self.identity.resolve(raw_token)


class ServiceAccountAuthenticationProvider:
    def __init__(self, service_accounts: ServiceAccountService) -> None:
        self.service_accounts = service_accounts

    def resolve(self, raw_token: str) -> Principal:
        try:
            return self.service_accounts.resolve_token(raw_token)
        except ServiceAccountError as exc:
            raise IdentityError("invalid service-account token") from exc


class CompositeAuthenticationProvider:
    def __init__(
        self,
        human_provider: AuthenticationProvider,
        service_account_provider: ServiceAccountAuthenticationProvider,
    ) -> None:
        self.human_provider = human_provider
        self.service_account_provider = service_account_provider

    def resolve(self, raw_token: str) -> Principal:
        if raw_token.startswith("rp_svc_"):
            return self.service_account_provider.resolve(raw_token)
        return self.human_provider.resolve(raw_token)


class OIDCAuthenticationProvider:
    """OIDC-ready seam; deployments inject a verifier that validates issuer, audience, signature and expiry."""

    def __init__(self, verifier: Callable[[str], Principal] | None = None) -> None:
        self.verifier = verifier

    def resolve(self, raw_token: str) -> Principal:
        if self.verifier is None:
            raise IdentityProviderUnavailable("external identity verification is not configured")
        principal = self.verifier(raw_token)
        if not isinstance(principal, Principal):
            raise IdentityProviderUnavailable("external identity verifier returned no principal")
        if principal.auth_method == "oidc":
            return principal
        return replace(principal, auth_method="oidc")


def build_authentication_provider(
    mode: str,
    identity: IdentityService,
    *,
    service_accounts: ServiceAccountService | None = None,
    oidc_verifier: Callable[[str], Principal] | None = None,
) -> AuthenticationProvider:
    """Select a provider without embedding IdP secrets or accepting unverified claims."""
    if mode == "opaque":
        human_provider: AuthenticationProvider = OpaqueSessionProvider(identity)
    elif mode == "oidc":
        human_provider = OIDCAuthenticationProvider(oidc_verifier)
    else:
        raise ValueError("unsupported authentication provider")
    if service_accounts is None:
        return human_provider
    return CompositeAuthenticationProvider(human_provider, ServiceAccountAuthenticationProvider(service_accounts))


class StepUpPolicy(Protocol):
    """Hook for MFA or equivalent step-up enforcement at sensitive permissions."""

    def is_satisfied(self, principal: Principal, permission: str) -> bool:
        """Return whether the principal has a current step-up for the permission."""


class MfaStepUpPolicy:
    def __init__(self, required_permissions: frozenset[str] | None = None) -> None:
        self.required_permissions = (
            frozenset({"manage_identity", "view_audit"})
            if required_permissions is None
            else required_permissions
        )

    def is_satisfied(self, principal: Principal, permission: str) -> bool:
        if permission not in self.required_permissions:
            return True
        expiry = principal.step_up_expires_at
        return principal.mfa_verified and expiry is not None and expiry > datetime.now(timezone.utc)


class RateLimiter:
    def __init__(self, limit: int = 120, window_seconds: int = 60) -> None:
        self.limit = max(1, limit)
        self.window_seconds = window_seconds
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            events = [event for event in self._events[key] if event > cutoff]
            if len(events) >= self.limit:
                self._events[key] = events
                return False
            events.append(now)
            self._events[key] = events
            return True


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "platform_admin": {"read", "analyze", "manage_cases", "manage_identity", "view_audit"},
    "tenant_admin": {"read", "analyze", "manage_cases", "manage_identity", "view_audit"},
    "analyst": {"read", "analyze", "manage_cases"},
    "remediation_manager": {"read", "manage_cases"},
    "viewer": {"read"},
}


def _has_permission(principal: Principal, permission: str) -> bool:
    return principal.has_permission(permission) or principal.has_role("platform_admin") or any(
        permission in ROLE_PERMISSIONS.get(role, set()) for role in principal.roles
    )


def _audit(request: Request, operation: str, details: dict[str, object], *, actor: str = "anonymous") -> None:
    application = request.scope.get("app")
    logger = getattr(getattr(application, "state", None), "audit_logger", None)
    if isinstance(logger, AuditLogger):
        logger.record(operation, details, actor=actor)


def rate_limit_dependency(limiter: RateLimiter) -> Callable:
    async def dependency(request: Request) -> None:
        if not limiter.allow(_client_key(request)):
            _audit(request, "auth.rate_limited", {"route": route_template(request)})
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")

    return dependency


def role_dependency(role: str) -> Callable:
    async def dependency(request: Request) -> Principal:
        principal = getattr(request.state, "principal", None)
        if principal is None or not principal.has_role(role):
            _audit(
                request,
                "authz.role_denied",
                {"required_role": role, "route": route_template(request)},
                actor=getattr(principal, "username", "anonymous"),
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return principal

    return dependency


def permission_dependency(permission: str, *, step_up_policy: StepUpPolicy | None = None) -> Callable:
    async def dependency(request: Request) -> Principal:
        principal = getattr(request.state, "principal", None)
        if principal is None or not _has_permission(principal, permission):
            _audit(
                request,
                "authz.permission_denied",
                {"required_permission": permission, "route": route_template(request)},
                actor=getattr(principal, "username", "anonymous"),
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        if step_up_policy is not None and not step_up_policy.is_satisfied(principal, permission):
            _audit(
                request,
                "authz.step_up_required",
                {"permission": permission, "route": route_template(request)},
                actor=principal.username,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="step-up authentication required")
        return principal

    return dependency


def step_up_dependency(policy: StepUpPolicy, permission: str) -> Callable:
    async def dependency(request: Request) -> Principal:
        principal = getattr(request.state, "principal", None)
        if principal is None or not policy.is_satisfied(principal, permission):
            _audit(
                request,
                "authz.step_up_required",
                {"permission": permission, "route": route_template(request)},
                actor=getattr(principal, "username", "anonymous"),
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="step-up authentication required")
        return principal

    return dependency


def principal_dependency(
    identity: IdentityService,
    limiter: RateLimiter,
    permission: str | None = None,
    *,
    provider: AuthenticationProvider | None = None,
) -> Callable:
    selected_provider = provider or OpaqueSessionProvider(identity)

    async def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Security(BEARER),  # noqa: B008
    ) -> AsyncIterator[Principal]:
        if credentials is None or credentials.scheme.lower() != "bearer":
            _audit(request, "auth.failed", {"reason": "missing_or_invalid_bearer"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not limiter.allow(f"{_client_key(request)}:{credentials.credentials[:16]}"):
            _audit(request, "auth.rate_limited", {"route": route_template(request)})
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")
        try:
            principal = selected_provider.resolve(credentials.credentials)
        except IdentityProviderUnavailable as exc:
            _audit(request, "auth.provider_unavailable", {"provider": type(selected_provider).__name__})
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authentication unavailable",
            ) from exc
        except IdentityError as exc:
            _audit(request, "auth.failed", {"reason": "invalid_or_expired_session"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or expired access token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if permission and not _has_permission(principal, permission):
            _audit(
                request,
                "authz.permission_denied",
                {"required_permission": permission, "route": route_template(request)},
                actor=principal.username,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        token = set_principal(principal)
        request.state.principal = principal
        request.state.access_token = credentials.credentials
        request.state.auth_method = principal.auth_method
        try:
            yield principal
        finally:
            reset_principal(token)

    return dependency
