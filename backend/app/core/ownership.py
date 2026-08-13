from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from app.core.request_context import Principal


class OwnershipDenied(PermissionError):
    """Raised when an authenticated principal lacks same-tenant ownership access."""


@dataclass(frozen=True)
class OwnershipDecision:
    allowed: bool
    reason: Literal["owner", "manager", "tenant_mismatch", "not_found", "denied"]


def check_tenant(resource_tenant_id: str | None, principal: Principal) -> OwnershipDecision:
    """Return a non-sensitive tenant decision for a resource or child record."""
    if not resource_tenant_id:
        return OwnershipDecision(False, "not_found")
    if resource_tenant_id != principal.tenant_id:
        return OwnershipDecision(False, "tenant_mismatch")
    return OwnershipDecision(True, "owner")


def require_same_tenant(resource: Any, principal: Principal) -> Any:
    """Return a resource only when its persisted tenant matches the principal."""
    decision = check_tenant(getattr(resource, "tenant_id", None) if resource is not None else None, principal)
    if not decision.allowed:
        raise KeyError("Resource not found")
    return resource


def require_tenant_ids(principal: Principal, *tenant_ids: str | None) -> None:
    """Require every supplied tenant ID to match the authenticated tenant."""
    if any(tenant_id != principal.tenant_id for tenant_id in tenant_ids):
        raise KeyError("Resource not found")


def require_owner_or_manager(
    resource: Any,
    principal: Principal,
    *,
    owner_fields: tuple[str, ...] = ("owner", "created_by"),
) -> Any:
    """Enforce tenant isolation and owner/manager access without trusting request fields."""
    require_same_tenant(resource, principal)
    if principal.has_role("platform_admin") or principal.has_role("tenant_admin"):
        return resource
    owners = {getattr(resource, field, None) for field in owner_fields}
    if principal.username in owners or principal.user_id in owners:
        return resource
    raise OwnershipDenied("resource ownership is required")


def tenant_query(query: Any, model: Any, principal_or_tenant: Principal | str) -> Any:
    """Apply the canonical tenant predicate to a query or worker-owned tenant ID."""
    tenant_id = (
        principal_or_tenant.tenant_id
        if isinstance(principal_or_tenant, Principal)
        else principal_or_tenant
    )
    return query.filter(model.tenant_id == tenant_id)
