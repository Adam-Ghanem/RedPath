"""add access governance records

Revision ID: 7c9d2a4e1f6b
Revises: 22d614b2aac8
Create Date: 2026-08-14 04:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "7c9d2a4e1f6b"
down_revision = "22d614b2aac8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "access_requests" not in tables:
        op.create_table(
            "access_requests",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("requester_user_id", sa.String(length=36), nullable=False),
            sa.Column("requester_actor", sa.String(length=128), nullable=False),
            sa.Column("requested_scopes", sa.JSON(), nullable=False),
            sa.Column("reason", sa.String(length=500), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("approver_user_id", sa.String(length=36), nullable=True),
            sa.Column("approver_actor", sa.String(length=128), nullable=True),
            sa.Column("decision_comment", sa.String(length=500), nullable=True),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["requester_user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_access_requests_tenant_id", "access_requests", ["tenant_id"])
        op.create_index("ix_access_requests_requester_user_id", "access_requests", ["requester_user_id"])
        op.create_index("ix_access_requests_status", "access_requests", ["status"])
        op.create_index("ix_access_requests_expires_at", "access_requests", ["expires_at"])
        op.create_index("ix_access_requests_approver_user_id", "access_requests", ["approver_user_id"])

    if "access_governance_events" not in tables:
        op.create_table(
            "access_governance_events",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("actor_user_id", sa.String(length=36), nullable=True),
            sa.Column("actor", sa.String(length=128), nullable=False),
            sa.Column("resource_id", sa.String(length=36), nullable=True),
            sa.Column("outcome", sa.String(length=32), nullable=False),
            sa.Column("metadata_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_access_governance_events_tenant_id", "access_governance_events", ["tenant_id"])
        op.create_index("ix_access_governance_events_event_type", "access_governance_events", ["event_type"])
        op.create_index("ix_access_governance_events_actor_user_id", "access_governance_events", ["actor_user_id"])
        op.create_index("ix_access_governance_events_resource_id", "access_governance_events", ["resource_id"])
        op.create_index("ix_access_governance_events_outcome", "access_governance_events", ["outcome"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "access_governance_events" in tables:
        op.drop_table("access_governance_events")
    if "access_requests" in tables:
        op.drop_table("access_requests")
