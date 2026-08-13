from __future__ import annotations

from collections import defaultdict
from collections.abc import AsyncIterator
from threading import Lock
from time import monotonic
from typing import Callable

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.request_context import Principal, reset_principal, set_principal
from app.services.identity import IdentityError, IdentityService

BEARER = HTTPBearer(auto_error=False)


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
    return principal.has_role("platform_admin") or any(
        permission in ROLE_PERMISSIONS.get(role, set()) for role in principal.roles
    )


def rate_limit_dependency(limiter: RateLimiter) -> Callable:
    async def dependency(request: Request) -> None:
        if not limiter.allow(_client_key(request)):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")

    return dependency


def role_dependency(role: str) -> Callable:
    async def dependency(request: Request) -> Principal:
        principal = getattr(request.state, "principal", None)
        if principal is None or not principal.has_role(role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return principal

    return dependency


def permission_dependency(permission: str) -> Callable:
    async def dependency(request: Request) -> Principal:
        principal = getattr(request.state, "principal", None)
        if principal is None or not _has_permission(principal, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return principal

    return dependency


def principal_dependency(identity: IdentityService, limiter: RateLimiter, permission: str | None = None) -> Callable:
    async def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Security(BEARER),  # noqa: B008
    ) -> AsyncIterator[Principal]:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not limiter.allow(f"{_client_key(request)}:{credentials.credentials[:16]}"):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")
        try:
            principal = identity.resolve(credentials.credentials)
        except IdentityError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or expired access token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if permission and not _has_permission(principal, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        token = set_principal(principal)
        request.state.principal = principal
        request.state.access_token = credentials.credentials
        try:
            yield principal
        finally:
            reset_principal(token)

    return dependency
