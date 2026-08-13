from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Callable
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from sqlalchemy import and_

from app.core.request_context import Principal
from app.db.models import AuthSession, Membership, Tenant, User, utcnow
from app.schemas.identity import (
    AuthBootstrapRequest,
    AuthLoginRequest,
    AuthTokenResponse,
    TenantCreateRequest,
    TenantResponse,
    UserCreateRequest,
    UserResponse,
)

SessionFactory = Callable[[], object]

ACCESS_TOKEN_TTL = timedelta(minutes=15)


class IdentityError(Exception):
    pass


class BootstrapAlreadyCompleted(IdentityError):
    pass


class InvalidCredentials(IdentityError):
    pass


class DuplicateIdentity(IdentityError):
    pass


class IdentityService:
    def __init__(self, session_factory: SessionFactory, bootstrap_token: str) -> None:
        self.session_factory = session_factory
        self.bootstrap_token = bootstrap_token
        self.password_hasher = PasswordHasher()

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _issue_token(self, session, user: User, tenant: Tenant, roles: list[str]) -> AuthTokenResponse:
        raw_token = secrets.token_urlsafe(48)
        expires_at = utcnow() + ACCESS_TOKEN_TTL
        session.add(
            AuthSession(
                id=str(uuid4()),
                user_id=user.id,
                tenant_id=tenant.id,
                token_hash=self._token_hash(raw_token),
                session_version=user.session_version,
                expires_at=expires_at,
            )
        )
        session.commit()
        return AuthTokenResponse(
            access_token=raw_token,
            expires_at=expires_at,
            user_id=user.id,
            username=user.username,
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            roles=sorted(roles),
        )

    def bootstrap(self, request: AuthBootstrapRequest) -> AuthTokenResponse:
        if not secrets.compare_digest(request.bootstrap_token, self.bootstrap_token):
            raise InvalidCredentials("invalid bootstrap credentials")
        with self.session_factory() as session:
            if session.query(User).count() > 0:
                raise BootstrapAlreadyCompleted("bootstrap has already been completed")
            tenant = Tenant(id=str(uuid4()), slug=request.tenant_slug, name=request.tenant_name)
            user = User(
                id=str(uuid4()),
                tenant_id=tenant.id,
                username=request.username,
                password_hash=self.password_hasher.hash(request.password),
            )
            session.add(tenant)
            session.add(user)
            session.add(Membership(id=str(uuid4()), user_id=user.id, tenant_id=tenant.id, role="tenant_admin"))
            session.add(Membership(id=str(uuid4()), user_id=user.id, tenant_id=tenant.id, role="platform_admin"))
            session.flush()
            return self._issue_token(session, user, tenant, ["tenant_admin", "platform_admin"])

    def login(self, request: AuthLoginRequest) -> AuthTokenResponse:
        with self.session_factory() as session:
            row = (
                session.query(User, Tenant)
                .join(Tenant, Tenant.id == User.tenant_id)
                .filter(
                    and_(
                        User.username == request.username,
                        Tenant.slug == request.tenant_slug,
                        User.is_active.is_(True),
                        Tenant.is_active.is_(True),
                    )
                )
                .first()
            )
            if row is None:
                raise InvalidCredentials("invalid credentials")
            user, tenant = row
            try:
                valid = self.password_hasher.verify(user.password_hash, request.password)
            except (VerifyMismatchError, InvalidHash):
                valid = False
            if not valid:
                raise InvalidCredentials("invalid credentials")
            memberships = (
                session.query(Membership)
                .filter_by(user_id=user.id, tenant_id=tenant.id, is_active=True)
                .order_by(Membership.role.asc())
                .all()
            )
            if not memberships:
                raise InvalidCredentials("invalid credentials")
            return self._issue_token(session, user, tenant, [membership.role for membership in memberships])

    def resolve(self, raw_token: str) -> Principal:
        now = utcnow()
        with self.session_factory() as session:
            row = (
                session.query(AuthSession, User, Tenant)
                .join(User, User.id == AuthSession.user_id)
                .join(Tenant, Tenant.id == AuthSession.tenant_id)
                .filter(
                    AuthSession.token_hash == self._token_hash(raw_token),
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                    User.is_active.is_(True),
                    Tenant.is_active.is_(True),
                )
                .first()
            )
            if row is None:
                raise InvalidCredentials("invalid or expired access token")
            auth_session, user, tenant = row
            if auth_session.session_version != user.session_version:
                raise InvalidCredentials("session is no longer valid")
            memberships = (
                session.query(Membership)
                .filter_by(user_id=user.id, tenant_id=tenant.id, is_active=True)
                .order_by(Membership.role.asc())
                .all()
            )
            if not memberships:
                raise InvalidCredentials("user has no active tenant membership")
            step_up_expires_at = auth_session.mfa_verified_until
            mfa_verified = step_up_expires_at is not None and step_up_expires_at > now
            return Principal(
                user_id=user.id,
                username=user.username,
                tenant_id=tenant.id,
                tenant_slug=tenant.slug,
                roles=tuple(sorted(membership.role for membership in memberships)),
                session_version=user.session_version,
                mfa_verified=mfa_verified,
                step_up_expires_at=step_up_expires_at if mfa_verified else None,
            )

    def record_step_up(self, principal: Principal, ttl_minutes: int) -> datetime:
        if ttl_minutes < 5 or ttl_minutes > 60:
            raise InvalidCredentials("step-up TTL is outside the allowed window")
        now = utcnow()
        expires_at = now + timedelta(minutes=ttl_minutes)
        with self.session_factory() as session:
            user = (
                session.query(User)
                .filter_by(id=principal.user_id, tenant_id=principal.tenant_id, is_active=True)
                .first()
            )
            if user is None:
                raise InvalidCredentials("authenticated user is no longer active")
            session.query(AuthSession).filter_by(
                user_id=user.id,
                tenant_id=principal.tenant_id,
                revoked_at=None,
            ).filter(AuthSession.expires_at > now).update(
                {"mfa_verified_until": expires_at}, synchronize_session=False
            )
            session.commit()
        return expires_at

    def revoke(self, raw_token: str) -> bool:
        with self.session_factory() as session:
            auth_session = session.query(AuthSession).filter_by(token_hash=self._token_hash(raw_token)).first()
            if auth_session is None or auth_session.revoked_at is not None:
                return False
            auth_session.revoked_at = utcnow()
            session.commit()
            return True

    def revoke_all(self, principal: Principal) -> int:
        with self.session_factory() as session:
            user = (
                session.query(User)
                .filter_by(id=principal.user_id, tenant_id=principal.tenant_id, is_active=True)
                .first()
            )
            if user is None:
                raise InvalidCredentials("authenticated user is no longer active")
            now = utcnow()
            sessions = (
                session.query(AuthSession)
                .filter_by(user_id=user.id, tenant_id=principal.tenant_id)
                .filter(AuthSession.revoked_at.is_(None))
                .all()
            )
            for auth_session in sessions:
                auth_session.revoked_at = now
                auth_session.mfa_verified_until = None
            user.session_version += 1
            session.commit()
            return len(sessions)

    def create_tenant(self, request: TenantCreateRequest) -> TenantResponse:
        with self.session_factory() as session:
            if session.query(Tenant).filter_by(slug=request.slug).first():
                raise DuplicateIdentity("tenant slug already exists")
            tenant = Tenant(id=str(uuid4()), slug=request.slug, name=request.name)
            user = User(
                id=str(uuid4()),
                tenant_id=tenant.id,
                username=request.admin_username,
                password_hash=self.password_hasher.hash(request.admin_password),
            )
            session.add(tenant)
            session.add(user)
            session.add(Membership(id=str(uuid4()), user_id=user.id, tenant_id=tenant.id, role="tenant_admin"))
            session.commit()
            return TenantResponse(
                tenant_id=tenant.id,
                slug=tenant.slug,
                name=tenant.name,
                is_active=tenant.is_active,
            )

    def create_user(self, principal: Principal, request: UserCreateRequest) -> UserResponse:
        with self.session_factory() as session:
            if session.query(User).filter_by(tenant_id=principal.tenant_id, username=request.username).first():
                raise DuplicateIdentity("username already exists in this tenant")
            user = User(
                id=str(uuid4()),
                tenant_id=principal.tenant_id,
                username=request.username,
                password_hash=self.password_hasher.hash(request.password),
            )
            session.add(user)
            for role in request.roles:
                session.add(
                    Membership(
                        id=str(uuid4()),
                        user_id=user.id,
                        tenant_id=principal.tenant_id,
                        role=role,
                    )
                )
            session.commit()
            session.refresh(user)
            return UserResponse(
                user_id=user.id,
                username=user.username,
                tenant_id=principal.tenant_id,
                roles=sorted(request.roles),
                is_active=user.is_active,
                created_at=user.created_at,
            )

    def list_users(self, principal: Principal) -> list[UserResponse]:
        with self.session_factory() as session:
            users = session.query(User).filter_by(tenant_id=principal.tenant_id).order_by(User.username.asc()).all()
            memberships = session.query(Membership).filter_by(tenant_id=principal.tenant_id, is_active=True).all()
        roles_by_user: dict[str, list[str]] = {}
        for membership in memberships:
            roles_by_user.setdefault(membership.user_id, []).append(membership.role)
        return [
            UserResponse(
                user_id=user.id,
                username=user.username,
                tenant_id=user.tenant_id,
                roles=sorted(roles_by_user.get(user.id, [])),
                is_active=user.is_active,
                created_at=user.created_at,
            )
            for user in users
        ]
