from dataclasses import dataclass
from typing import Callable

from fastapi import Header, HTTPException, status

from app.core.config import Settings


@dataclass(frozen=True)
class Principal:
    """Authenticated RedPath actor used for server-side authorization and audit attribution."""

    actor: str
    role: str


_ROLE_RANK = {
    "soc_analyst": 10,
    "remediation_owner": 10,
    "soc_lead": 20,
    "platform_admin": 30,
}


def _configured_credentials(settings: Settings) -> dict[str, str]:
    credentials: dict[str, str] = {}
    for entry in settings.redpath_api_keys.split(","):
        token, separator, role = entry.strip().partition(":")
        if separator and token and role in _ROLE_RANK:
            credentials[token] = role
    return credentials


def require_roles(settings: Settings, allowed_roles: set[str]) -> Callable[..., Principal]:
    """Create a FastAPI dependency with bearer-token authentication and role authorization.

    Tokens are supplied only through ``REDPATH_API_KEYS`` as ``token:role`` pairs. The
    bearer token is never echoed in responses or audit records; callers provide an actor
    label separately for attribution.
    """

    def dependency(
        authorization: str | None = Header(default=None),
        x_redpath_actor: str | None = Header(default=None),
    ) -> Principal:
        credentials = _configured_credentials(settings)
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="governance authentication is not configured",
            )
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer authentication required")
        token = authorization.removeprefix("Bearer ").strip()
        role = credentials.get(token)
        if role is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")
        if role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        actor = (x_redpath_actor or role).strip()
        if not actor or len(actor) > 128:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid actor label")
        return Principal(actor=actor, role=role)

    return dependency


def role_allows(role: str, required_role: str) -> bool:
    return _ROLE_RANK.get(role, -1) >= _ROLE_RANK.get(required_role, 10_000)
