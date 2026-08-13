from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """Authenticated actor and the tenant selected for this request."""

    user_id: str
    username: str
    tenant_id: str
    tenant_slug: str
    roles: tuple[str, ...]
    session_version: int

    def has_role(self, role: str) -> bool:
        return role in self.roles


_current_principal: ContextVar[Principal | None] = ContextVar("redpath_principal", default=None)


def set_principal(principal: Principal):
    return _current_principal.set(principal)


def reset_principal(token) -> None:
    _current_principal.reset(token)


def get_principal() -> Principal:
    principal = _current_principal.get()
    if principal is None:
        raise RuntimeError("authenticated principal is required")
    return principal


def maybe_principal() -> Principal | None:
    return _current_principal.get()


def current_tenant_id() -> str:
    return get_principal().tenant_id


def current_actor() -> str:
    principal = maybe_principal()
    return principal.username if principal else "system"
