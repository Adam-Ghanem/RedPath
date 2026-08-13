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

SERVICE_ACCOUNT_SCOPES = {"read", "analyze", "manage_cases", "view_audit"}


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
    auth_method: str = "opaque"
    mfa_verified: bool = False
    step_up_expires_at: datetime | None = None


class AuthSessionRevokeResponse(BaseModel):
    revoked_sessions: int = Field(ge=0)


class MfaStepUpRequest(BaseModel):
    assurance_level: Literal["aal2", "aal3"] = "aal2"
    ttl_minutes: int = Field(default=15, ge=5, le=60)


class MfaStepUpResponse(BaseModel):
    mfa_verified: bool
    step_up_expires_at: datetime


class ServiceAccountCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    description: str = Field(default="", max_length=255)
    scopes: list[str] = Field(min_length=1, max_length=4)
    expires_at: datetime | None = None

    @field_validator("scopes")
    @classmethod
    def scopes_must_be_known(cls, scopes: list[str]) -> list[str]:
        if len(set(scopes)) != len(scopes) or any(scope not in SERVICE_ACCOUNT_SCOPES for scope in scopes):
            raise ValueError("scopes must be unique and drawn from the supported service-account scope set")
        return scopes


class ServiceAccountResponse(BaseModel):
    service_account_id: str
    tenant_id: str
    name: str
    description: str
    scopes: list[str]
    created_by: str
    is_active: bool
    expires_at: datetime | None
    last_rotated_at: datetime | None
    token_version: int
    created_at: datetime


class ServiceAccountTokenResponse(BaseModel):
    service_account: ServiceAccountResponse
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: datetime


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
