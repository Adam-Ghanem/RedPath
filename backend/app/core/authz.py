from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request, status

from app.core.audit import AuditLogger
from app.core.errors import route_template

ALLOWED_ATTACK_PATH_ROLES = frozenset({"analyst", "risk_analyst", "security_admin", "platform_admin"})


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    tenant_ids: frozenset[str]


def _principal_from_state(value: Any) -> Principal | None:
    if isinstance(value, Principal):
        return value
    if not isinstance(value, dict):
        return None
    subject = value.get("subject")
    roles = value.get("roles")
    tenant_ids = value.get("tenant_ids")
    if not isinstance(subject, str) or not subject or not isinstance(roles, (list, set, tuple)):
        return None
    if not isinstance(tenant_ids, (list, set, tuple)):
        return None
    if not all(isinstance(role, str) for role in roles) or not all(isinstance(item, str) for item in tenant_ids):
        return None
    return Principal(subject=subject, roles=frozenset(roles), tenant_ids=frozenset(tenant_ids))


def _audit_denial(request: Request, operation: str, actor: str = "anonymous") -> None:
    application = request.scope.get("app")
    logger = getattr(getattr(application, "state", None), "audit_logger", None)
    if isinstance(logger, AuditLogger):
        logger.record(operation, {"route": route_template(request)}, actor=actor)


def require_authenticated_analyst(request: Request) -> Principal:
    """Resolve a principal injected by platform auth middleware; never trusts request headers."""
    principal = _principal_from_state(getattr(request.state, "principal", None))
    if principal is None:
        _audit_denial(request, "authz.attack_path_authentication_denied")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not principal.roles.intersection(ALLOWED_ATTACK_PATH_ROLES):
        _audit_denial(request, "authz.attack_path_role_denied", principal.subject)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Attack-path analysis role required")
    return principal


def authorize_tenant(principal: Principal, tenant_id: str) -> None:
    if "platform_admin" not in principal.roles and tenant_id not in principal.tenant_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant access denied")
