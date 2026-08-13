from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    tenant_id: str


def require_siem_reader(settings: Settings) -> Callable[..., Principal]:
    """Build a fail-closed bearer dependency bound to the configured SIEM reader."""

    def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),  # noqa: B008
        tenant_header: str | None = Header(default=None, alias="X-RedPath-Tenant"),
    ) -> Principal:
        if not settings.siem_ingestion_api_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="SIEM ingestion authentication is not configured",
            )
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer authentication required")
        if not secrets.compare_digest(credentials.credentials, settings.siem_ingestion_api_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid SIEM reader credentials")
        if not tenant_header:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="X-RedPath-Tenant header is required")
        if tenant_header not in settings.siem_allowed_tenant_list:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant is not authorized for this reader",
            )
        return Principal(actor="siem-reader", role="siem_reader", tenant_id=tenant_header)

    return dependency
