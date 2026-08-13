from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

ROLE_NAMES = {
    "platform_admin",
    "tenant_admin",
    "analyst",
    "viewer",
    "remediation_manager",
}


class AuthBootstrapRequest(BaseModel):
    bootstrap_token: str = Field(min_length=16, max_length=256)
    tenant_slug: str = Field(min_length=2, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]{1,127}$")
    tenant_name: str = Field(min_length=2, max_length=255)
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")
    password: str = Field(min_length=12, max_length=256)


class AuthLoginRequest(BaseModel):
    tenant_slug: str = Field(min_length=2, max_length=128)
    username: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: datetime
    user_id: str
    username: str
    tenant_id: str
    tenant_slug: str
    roles: list[str]


class AuthMeResponse(BaseModel):
    user_id: str
    username: str
    tenant_id: str
    tenant_slug: str
    roles: list[str]
    session_version: int


class AuthSessionRevokeResponse(BaseModel):
    revoked_sessions: int = Field(ge=0)


class TenantCreateRequest(BaseModel):
    slug: str = Field(min_length=2, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]{1,127}$")
    name: str = Field(min_length=2, max_length=255)
    admin_username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")
    admin_password: str = Field(min_length=12, max_length=256)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")
    password: str = Field(min_length=12, max_length=256)
    roles: list[str] = Field(min_length=1, max_length=5)

    @field_validator("roles")
    @classmethod
    def roles_must_be_known(cls, roles: list[str]) -> list[str]:
        if len(set(roles)) != len(roles) or any(role not in ROLE_NAMES for role in roles):
            raise ValueError("roles must be unique and drawn from the supported role set")
        return roles


class UserResponse(BaseModel):
    user_id: str
    username: str
    tenant_id: str
    roles: list[str]
    is_active: bool
    created_at: datetime


class TenantResponse(BaseModel):
    tenant_id: str
    slug: str
    name: str
    is_active: bool
