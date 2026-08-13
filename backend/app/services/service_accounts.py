from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta, timezone
from typing import Callable
from uuid import uuid4

from app.core.request_context import Principal
from app.db.models import ServiceAccount, ServiceAccountToken, utcnow
from app.schemas.identity import (
    ServiceAccountCreateRequest,
    ServiceAccountResponse,
    ServiceAccountTokenResponse,
)

SessionFactory = Callable[[], object]


class ServiceAccountError(Exception):
    """Base class for safe service-account lifecycle failures."""


class ServiceAccountNotFound(ServiceAccountError):
    pass


class ServiceAccountInvalid(ServiceAccountError):
    pass


def _utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class ServiceAccountService:
    def __init__(self, session_factory: SessionFactory, *, max_ttl_days: int = 90, token_ttl_minutes: int = 60) -> None:
        self.session_factory = session_factory
        self.max_ttl_days = max_ttl_days
        self.token_ttl_minutes = token_ttl_minutes

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _response(row: ServiceAccount) -> ServiceAccountResponse:
        return ServiceAccountResponse(
            service_account_id=row.id,
            tenant_id=row.tenant_id,
            name=row.name,
            description=row.description,
            scopes=list(row.scopes or []),
            created_by=row.created_by,
            is_active=row.is_active,
            expires_at=row.expires_at,
            last_rotated_at=row.last_rotated_at,
            token_version=row.token_version,
            created_at=row.created_at,
        )

    def _issue_token(self, session, row: ServiceAccount) -> ServiceAccountTokenResponse:
        now = utcnow()
        account_expires_at = _utc(row.expires_at)
        expires_at = min(
            now + timedelta(minutes=self.token_ttl_minutes),
            account_expires_at or now + timedelta(days=self.max_ttl_days),
        )
        if expires_at <= now:
            raise ServiceAccountInvalid("service account is expired")
        raw_token = f"rp_svc_{secrets.token_urlsafe(48)}"
        session.add(
            ServiceAccountToken(
                id=str(uuid4()),
                service_account_id=row.id,
                tenant_id=row.tenant_id,
                token_hash=self._hash(raw_token),
                token_version=row.token_version,
                expires_at=expires_at,
            )
        )
        session.commit()
        return ServiceAccountTokenResponse(
            service_account=self._response(row),
            access_token=raw_token,
            expires_at=expires_at,
        )

    def create(self, principal: Principal, request: ServiceAccountCreateRequest) -> ServiceAccountTokenResponse:
        now = utcnow()
        if request.expires_at is not None:
            expires_at = request.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= now or expires_at > now + timedelta(days=self.max_ttl_days):
                raise ServiceAccountInvalid("service-account expiry is outside the allowed window")
        else:
            expires_at = now + timedelta(days=self.max_ttl_days)
        with self.session_factory() as session:
            if (
                session.query(ServiceAccount)
                .filter_by(tenant_id=principal.tenant_id, name=request.name, is_active=True)
                .first()
                is not None
            ):
                raise ServiceAccountInvalid("service-account name already exists")
            row = ServiceAccount(
                id=str(uuid4()),
                tenant_id=principal.tenant_id,
                name=request.name,
                description=request.description,
                scopes=list(request.scopes),
                created_by=principal.username,
                expires_at=expires_at,
                token_version=1,
            )
            session.add(row)
            session.flush()
            return self._issue_token(session, row)

    def list(self, principal: Principal) -> list[ServiceAccountResponse]:
        with self.session_factory() as session:
            rows = (
                session.query(ServiceAccount)
                .filter_by(tenant_id=principal.tenant_id)
                .order_by(ServiceAccount.name.asc())
                .all()
            )
        return [self._response(row) for row in rows]

    def rotate(self, principal: Principal, service_account_id: str) -> ServiceAccountTokenResponse:
        with self.session_factory() as session:
            row = (
                session.query(ServiceAccount)
                .filter_by(id=service_account_id, tenant_id=principal.tenant_id, is_active=True)
                .first()
            )
            if row is None:
                raise ServiceAccountNotFound("service account not found")
            now = utcnow()
            row.token_version += 1
            row.last_rotated_at = now
            session.query(ServiceAccountToken).filter_by(
                service_account_id=row.id,
                tenant_id=principal.tenant_id,
                revoked_at=None,
            ).update({"revoked_at": now}, synchronize_session=False)
            session.flush()
            return self._issue_token(session, row)

    def revoke(self, principal: Principal, service_account_id: str) -> ServiceAccountResponse:
        with self.session_factory() as session:
            row = (
                session.query(ServiceAccount)
                .filter_by(id=service_account_id, tenant_id=principal.tenant_id, is_active=True)
                .first()
            )
            if row is None:
                raise ServiceAccountNotFound("service account not found")
            now = utcnow()
            row.is_active = False
            row.token_version += 1
            row.last_rotated_at = now
            session.query(ServiceAccountToken).filter_by(
                service_account_id=row.id,
                tenant_id=principal.tenant_id,
                revoked_at=None,
            ).update({"revoked_at": now}, synchronize_session=False)
            session.commit()
            return self._response(row)

    def resolve_token(self, raw_token: str) -> Principal:
        now = utcnow()
        with self.session_factory() as session:
            row = (
                session.query(ServiceAccountToken, ServiceAccount)
                .join(ServiceAccount, ServiceAccount.id == ServiceAccountToken.service_account_id)
                .filter(
                    ServiceAccountToken.token_hash == self._hash(raw_token),
                    ServiceAccountToken.revoked_at.is_(None),
                    ServiceAccountToken.expires_at > now,
                    ServiceAccount.is_active.is_(True),
                    ServiceAccount.token_version == ServiceAccountToken.token_version,
                    (ServiceAccount.expires_at.is_(None) | (ServiceAccount.expires_at > now)),
                )
                .first()
            )
            if row is None:
                raise ServiceAccountInvalid("invalid or expired service-account token")
            token, account = row
            return Principal(
                user_id=f"service-account:{account.id}",
                username=f"service-account:{account.name}",
                tenant_id=account.tenant_id,
                tenant_slug=account.tenant_id,
                roles=("service_account",),
                session_version=token.token_version,
                auth_method="service_account",
                permissions=tuple(sorted(account.scopes or [])),
            )
