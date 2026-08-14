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


class PolicyEvaluationRequest(BaseModel):
    requested_scopes: list[str] = Field(min_length=1, max_length=4)
    requested_ttl_minutes: int = Field(default=60, ge=5, le=240)
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("requested_scopes")
    @classmethod
    def requested_scopes_must_be_known(cls, scopes: list[str]) -> list[str]:
        if len(set(scopes)) != len(scopes) or any(scope not in SERVICE_ACCOUNT_SCOPES for scope in scopes):
            raise ValueError("requested scopes must be unique and drawn from the supported scope set")
        return scopes


class PolicyEvaluationResponse(BaseModel):
    allowed: bool
    reason_code: str
    effective_scopes: list[str]
    requires_approval: bool
    requires_step_up: bool


class AccessRequestCreateRequest(PolicyEvaluationRequest):
    pass


class AccessRequestDecisionRequest(BaseModel):
    decision: Literal["approve", "deny"]
    comment: str = Field(default="", max_length=500)


class AccessRequestResponse(BaseModel):
    request_id: str
    tenant_id: str
    requester_user_id: str
    requester_actor: str
    requested_scopes: list[str]
    reason: str
    status: Literal["pending", "approved", "denied", "expired"]
    expires_at: datetime
    approver_actor: str | None
    decision_comment: str | None
    decided_at: datetime | None
    created_at: datetime


class ServiceAccountInventoryItem(ServiceAccountResponse):
    active_token_count: int = Field(ge=0)
    expired: bool
    next_token_expiry: datetime | None


class RevocationVerificationResponse(BaseModel):
    service_account_id: str
    token_version: int
    active_token_count: int = Field(ge=0)
    revoked_token_count: int = Field(ge=0)
    verified_at: datetime
    all_prior_tokens_revoked: bool


class SessionRiskResponse(BaseModel):
    risk_level: Literal["low", "medium", "high"]
    signals: list[str] = Field(max_length=8)
    requires_step_up: bool
    evaluated_at: datetime


class LeastPrivilegeReviewItem(ServiceAccountInventoryItem):
    excess_scopes: list[str]
    risk_level: Literal["low", "medium", "high"]


class LeastPrivilegeReviewResponse(BaseModel):
    generated_at: datetime
    tenant_id: str
    items: list[LeastPrivilegeReviewItem] = Field(max_length=200)


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
