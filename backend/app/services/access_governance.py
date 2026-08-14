from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol
from uuid import uuid4

from app.core.request_context import Principal
from app.db.models import AccessGovernanceEvent, AccessRequest, ServiceAccount, ServiceAccountToken, utcnow
from app.schemas.identity import (
    AccessRequestCreateRequest,
    AccessRequestDecisionRequest,
    AccessRequestResponse,
    LeastPrivilegeReviewItem,
    LeastPrivilegeReviewResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    RevocationVerificationResponse,
    ServiceAccountInventoryItem,
    SessionRiskResponse,
)

SessionFactory = Callable[[], object]
MAX_REPORT_ROWS = 200


class AccessGovernanceError(Exception):
    """Base class for safe access-governance failures."""


class AccessRequestNotFound(AccessGovernanceError):
    pass


class AccessRequestInvalid(AccessGovernanceError):
    pass


class SessionRiskEvaluator(Protocol):
    def evaluate(self, principal: Principal, context: Mapping[str, str]) -> SessionRiskResponse:
        """Return bounded risk metadata without inspecting secrets or raw request payloads."""


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _request_response(row: AccessRequest) -> AccessRequestResponse:
    return AccessRequestResponse(
        request_id=row.id,
        tenant_id=row.tenant_id,
        requester_user_id=row.requester_user_id,
        requester_actor=row.requester_actor,
        requested_scopes=list(row.requested_scopes or []),
        reason=row.reason,
        status=row.status,
        expires_at=row.expires_at,
        approver_actor=row.approver_actor,
        decision_comment=row.decision_comment,
        decided_at=row.decided_at,
        created_at=row.created_at,
    )


class DefaultSessionRiskEvaluator:
    def evaluate(self, principal: Principal, context: Mapping[str, str]) -> SessionRiskResponse:
        signals: list[str] = []
        if principal.auth_method == "service_account":
            signals.append("service_account_session")
        if principal.has_role("tenant_admin") or principal.has_role("platform_admin"):
            signals.append("privileged_role")
        if not principal.mfa_verified and any(
            role in principal.roles for role in ("tenant_admin", "platform_admin")
        ):
            signals.append("step_up_missing")
        if context.get("source") == "unknown":
            signals.append("unknown_source")
        if "step_up_missing" in signals:
            risk_level = "high"
        elif len(signals) >= 2:
            risk_level = "medium"
        else:
            risk_level = "low"
        return SessionRiskResponse(
            risk_level=risk_level,
            signals=signals[:8],
            requires_step_up=risk_level == "high",
            evaluated_at=utcnow(),
        )


class AccessGovernanceService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        max_report_rows: int = MAX_REPORT_ROWS,
        max_request_ttl_minutes: int = 240,
        risk_evaluator: SessionRiskEvaluator | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.max_report_rows = max(1, min(max_report_rows, MAX_REPORT_ROWS))
        self.max_request_ttl_minutes = max(5, min(max_request_ttl_minutes, 240))
        self.risk_evaluator = risk_evaluator or DefaultSessionRiskEvaluator()

    def _event(
        self,
        session,
        principal: Principal,
        event_type: str,
        outcome: str,
        *,
        resource_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        session.add(
            AccessGovernanceEvent(
                id=str(uuid4()),
                tenant_id=principal.tenant_id,
                event_type=event_type,
                actor_user_id=principal.user_id,
                actor=principal.username,
                resource_id=resource_id,
                outcome=outcome,
                metadata_json=metadata or {},
            )
        )

    def evaluate_policy(
        self,
        principal: Principal,
        request: PolicyEvaluationRequest,
    ) -> PolicyEvaluationResponse:
        scopes = sorted(set(request.requested_scopes))
        ttl_ok = 5 <= request.requested_ttl_minutes <= self.max_request_ttl_minutes
        requires_step_up = any(scope == "view_audit" for scope in scopes)
        response = PolicyEvaluationResponse(
            allowed=ttl_ok and bool(scopes),
            reason_code="within_policy" if ttl_ok else "ttl_exceeds_policy",
            effective_scopes=scopes,
            requires_approval=True,
            requires_step_up=requires_step_up,
        )
        with self.session_factory() as session:
            self._event(
                session,
                principal,
                "policy_evaluated",
                "allow" if response.allowed else "deny",
                metadata={
                    "requested_scope_count": len(scopes),
                    "requested_ttl_minutes": request.requested_ttl_minutes,
                    "requires_approval": response.requires_approval,
                    "requires_step_up": response.requires_step_up,
                    "reason_code": response.reason_code,
                },
            )
            session.commit()
        return response

    def create_request(self, principal: Principal, request: AccessRequestCreateRequest) -> AccessRequestResponse:
        evaluation = self.evaluate_policy(principal, request)
        if not evaluation.allowed:
            raise AccessRequestInvalid("access request is outside policy")
        now = utcnow()
        expires_at = now + timedelta(minutes=request.requested_ttl_minutes)
        with self.session_factory() as session:
            row = AccessRequest(
                id=str(uuid4()),
                tenant_id=principal.tenant_id,
                requester_user_id=principal.user_id,
                requester_actor=principal.username,
                requested_scopes=evaluation.effective_scopes,
                reason=request.reason,
                status="pending",
                expires_at=expires_at,
                created_at=now,
            )
            session.add(row)
            session.flush()
            self._event(
                session,
                principal,
                "jit_request_created",
                "pending",
                resource_id=row.id,
                metadata={
                    "requested_scope_count": len(evaluation.effective_scopes),
                    "reason_length": len(request.reason),
                },
            )
            session.commit()
            return _request_response(row)

    def list_requests(self, principal: Principal, *, include_all: bool = False) -> list[AccessRequestResponse]:
        now = utcnow()
        with self.session_factory() as session:
            pending = (
                session.query(AccessRequest)
                .filter_by(tenant_id=principal.tenant_id, status="pending")
                .filter(AccessRequest.expires_at <= now)
                .all()
            )
            for row in pending:
                row.status = "expired"
            query = session.query(AccessRequest).filter_by(tenant_id=principal.tenant_id)
            if not include_all:
                query = query.filter_by(requester_user_id=principal.user_id)
            rows = query.order_by(AccessRequest.created_at.desc()).limit(self.max_report_rows).all()
            session.commit()
            return [_request_response(row) for row in rows]

    def decide_request(
        self,
        principal: Principal,
        request_id: str,
        decision: AccessRequestDecisionRequest,
    ) -> AccessRequestResponse:
        now = utcnow()
        with self.session_factory() as session:
            row = (
                session.query(AccessRequest)
                .filter_by(id=request_id, tenant_id=principal.tenant_id, status="pending")
                .first()
            )
            if row is None:
                raise AccessRequestNotFound("access request not found")
            if principal.auth_method == "service_account":
                raise AccessRequestInvalid("service-account principals cannot approve access requests")
            if row.requester_user_id == principal.user_id:
                raise AccessRequestInvalid("requester cannot approve its own access request")
            if (_utc(row.expires_at) or now) <= now:
                row.status = "expired"
                session.commit()
                raise AccessRequestInvalid("access request has expired")
            row.status = "approved" if decision.decision == "approve" else "denied"
            row.approver_user_id = principal.user_id
            row.approver_actor = principal.username
            row.decision_comment = decision.comment or None
            row.decided_at = now
            self._event(
                session,
                principal,
                "jit_request_decided",
                row.status,
                resource_id=row.id,
                metadata={
                    "comment_length": len(decision.comment),
                    "requested_scope_count": len(row.requested_scopes or []),
                },
            )
            session.commit()
            return _request_response(row)

    def service_account_inventory(self, principal: Principal) -> list[ServiceAccountInventoryItem]:
        now = utcnow()
        with self.session_factory() as session:
            accounts = (
                session.query(ServiceAccount)
                .filter_by(tenant_id=principal.tenant_id)
                .order_by(ServiceAccount.name.asc())
                .limit(self.max_report_rows)
                .all()
            )
            account_ids = [account.id for account in accounts]
            tokens = (
                session.query(ServiceAccountToken)
                .filter(
                    ServiceAccountToken.tenant_id == principal.tenant_id,
                    ServiceAccountToken.service_account_id.in_(account_ids or ["__none__"]),
                )
                .all()
            )
        tokens_by_account: dict[str, list[ServiceAccountToken]] = {}
        for token in tokens:
            tokens_by_account.setdefault(token.service_account_id, []).append(token)
        result: list[ServiceAccountInventoryItem] = []
        for account in accounts:
            account_tokens = tokens_by_account.get(account.id, [])
            active_tokens = [
                token for token in account_tokens if token.revoked_at is None and (_utc(token.expires_at) or now) > now
            ]
            token_expiries = [_utc(token.expires_at) for token in active_tokens]
            result.append(
                ServiceAccountInventoryItem(
                    **{
                        **self._account_response(account).model_dump(),
                        "active_token_count": len(active_tokens),
                        "expired": account.expires_at is not None and _utc(account.expires_at) <= now,
                        "next_token_expiry": min(token_expiries) if token_expiries else None,
                    }
                )
            )
        return result

    @staticmethod
    def _account_response(account: ServiceAccount):
        from app.schemas.identity import ServiceAccountResponse

        return ServiceAccountResponse(
            service_account_id=account.id,
            tenant_id=account.tenant_id,
            name=account.name,
            description=account.description,
            scopes=list(account.scopes or []),
            created_by=account.created_by,
            is_active=account.is_active,
            expires_at=account.expires_at,
            last_rotated_at=account.last_rotated_at,
            token_version=account.token_version,
            created_at=account.created_at,
        )

    def verify_revocation(self, principal: Principal, service_account_id: str) -> RevocationVerificationResponse:
        now = utcnow()
        with self.session_factory() as session:
            account = (
                session.query(ServiceAccount)
                .filter_by(id=service_account_id, tenant_id=principal.tenant_id)
                .first()
            )
            if account is None:
                raise AccessRequestNotFound("service account not found")
            tokens = (
                session.query(ServiceAccountToken)
                .filter_by(service_account_id=account.id, tenant_id=principal.tenant_id)
                .all()
            )
        active_count = sum(
            1 for token in tokens if token.revoked_at is None and (_utc(token.expires_at) or now) > now
        )
        revoked_count = sum(1 for token in tokens if token.revoked_at is not None)
        return RevocationVerificationResponse(
            service_account_id=account.id,
            token_version=account.token_version,
            active_token_count=active_count,
            revoked_token_count=revoked_count,
            verified_at=now,
            all_prior_tokens_revoked=active_count == 0,
        )

    def session_risk(self, principal: Principal, context: Mapping[str, str]) -> SessionRiskResponse:
        return self.risk_evaluator.evaluate(principal, context)

    def least_privilege_review(self, principal: Principal) -> LeastPrivilegeReviewResponse:
        inventory = self.service_account_inventory(principal)
        items: list[LeastPrivilegeReviewItem] = []
        for account in inventory:
            excess = sorted(set(account.scopes) & {"manage_cases", "view_audit"})
            risk_level = "high" if "view_audit" in excess else "medium" if excess else "low"
            items.append(
                LeastPrivilegeReviewItem(
                    **account.model_dump(),
                    excess_scopes=excess,
                    risk_level=risk_level,
                )
            )
        generated_at = utcnow()
        with self.session_factory() as session:
            self._event(
                session,
                principal,
                "least_privilege_review_exported",
                "completed",
                metadata={"account_count": len(items), "row_limit": self.max_report_rows},
            )
            session.commit()
        return LeastPrivilegeReviewResponse(
            generated_at=generated_at,
            tenant_id=principal.tenant_id,
            items=items,
        )
