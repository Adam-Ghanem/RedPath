from __future__ import annotations

import pytest
from app.kernel.contracts import (
    CONTRACT_COMPATIBILITY_POLICY,
    ApiResponseEnvelope,
    EventEnvelope,
    IntegrationContext,
    IntegrationContextRequest,
    Page,
    PaginationMetadata,
    PaginationRequest,
)
from pydantic import ValidationError


def test_compatibility_policy_is_explicit_and_rejects_unknown_internal_versions() -> None:
    assert CONTRACT_COMPATIBILITY_POLICY.current_version == "1.0"
    assert CONTRACT_COMPATIBILITY_POLICY.accepts("1.0") is True
    assert CONTRACT_COMPATIBILITY_POLICY.accepts("2.0") is False

    with pytest.raises(ValidationError, match="unknown integration contract version"):
        IntegrationContext(
            tenant_id="tenant-a",
            actor="server-actor",
            request_id="request-1",
            contract_version="2.0",
        )
    with pytest.raises(ValidationError, match="unknown integration contract version"):
        IntegrationContextRequest(
            tenant_id="tenant-a",
            actor="server-actor",
            contract_version="2.0",
        )

    with pytest.raises(ValidationError, match="unknown event contract version"):
        EventEnvelope(
            event_id="event-1",
            event_type="integration.completed",
            contract_version="2.0",
            tenant_id="tenant-a",
            actor="server-actor",
            request_id="request-1",
        )


def test_event_envelope_is_tenant_scoped_scalar_only_and_secret_safe() -> None:
    event = EventEnvelope(
        event_id="event-1",
        event_type="integration.completed",
        tenant_id="tenant-a",
        actor="server-actor",
        request_id="request-1",
        payload={"count": 2, "dry_run": True, "status": "complete"},
    )
    assert event.schema_version == "1.0"
    assert event.contract_version == "1.0"
    assert event.tenant_id == "tenant-a"

    with pytest.raises(ValidationError, match="forbidden sensitive field"):
        EventEnvelope(
            event_id="event-2",
            event_type="integration.completed",
            tenant_id="tenant-a",
            actor="server-actor",
            request_id="request-2",
            payload={"token": "must-not-cross-contract"},
        )


def test_negotiation_request_does_not_accept_client_identity_fields() -> None:
    from app.kernel.contracts import CapabilityNegotiationRequest

    with pytest.raises(ValidationError):
        CapabilityNegotiationRequest.model_validate(
            {
                "request_id": "request-3",
                "contract_version": "2.0",
                "tenant_id": "client-supplied",
                "actor": "client-supplied",
            }
        )


def test_pagination_contract_is_bounded_and_typed() -> None:
    request = PaginationRequest(limit=100, cursor="42")
    page = Page[dict[str, str]](
        items=[{"key": "value"}],
        pagination=PaginationMetadata(limit=request.limit, next_cursor="43", has_more=True),
    )

    assert page.schema_version == "1.0"
    assert page.pagination.next_cursor == "43"

    with pytest.raises(ValidationError):
        PaginationRequest(limit=0)
    with pytest.raises(ValidationError):
        PaginationRequest(limit=101)
    with pytest.raises(ValidationError):
        PaginationRequest(limit=10, cursor="not-a-bounded-offset")


def test_api_response_envelope_carries_request_correlation() -> None:
    response = ApiResponseEnvelope[dict[str, str]](
        request_id="request-4",
        data={"status": "accepted"},
    )
    assert response.schema_version == "1.0"
    assert response.request_id == "request-4"
    assert response.data["status"] == "accepted"
