import hmac
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings

_bearer = HTTPBearer(auto_error=False)
_bearer_dependency = Depends(_bearer)


def build_discovery_authorizer(settings: Settings) -> Callable:
    """Create a fail-closed dependency for the single configured discovery tenant.

    AI-02 can replace this boundary with the shared RBAC provider without changing
    endpoint signatures. No tenant is accepted unless it matches server-side
    configuration, and an unset token disables the new resource endpoints.
    """

    def authorize(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = _bearer_dependency,
    ) -> str:
        if not settings.discovery_api_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Discovery API authentication is not configured",
            )
        if credentials is None or not hmac.compare_digest(credentials.credentials, settings.discovery_api_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid discovery operator credentials are required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        tenant_id = request.headers.get("x-redpath-tenant", settings.discovery_tenant_id)
        if not hmac.compare_digest(tenant_id, settings.discovery_tenant_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant is not authorized")
        return tenant_id

    return authorize
