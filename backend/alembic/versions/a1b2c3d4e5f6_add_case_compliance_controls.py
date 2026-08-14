"""Add case compliance controls for evidence, decisions, delegations, and reminders.

Revision ID: a1b2c3d4e5f6
Revises: 22d614b2aac8
Create Date: 2026-08-14 12:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "22d614b2aac8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add only tenant-scoped, metadata-only compliance records."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    risk_columns = {column["name"] for column in inspector.get_columns("risk_acceptances")}
    with op.batch_alter_table("risk_acceptances") as batch:
        if "delegation_id" not in risk_columns:
            batch.add_column(sa.Column("delegation_id", sa.String(length=36), nullable=True))
        if "delegated_from" not in risk_columns:
            batch.add_column(sa.Column("delegated_from", sa.String(length=128), nullable=True))
    indexes = {index["name"] for index in inspector.get_indexes("risk_acceptances")}
    if "ix_risk_acceptances_delegation_id" not in indexes:
        op.create_index("ix_risk_acceptances_delegation_id", "risk_acceptances", ["delegation_id"])

    if "remediation_verification_evidence" not in inspector.get_table_names():
        op.create_table(
            "remediation_verification_evidence",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("case_id", sa.String(length=36), nullable=True),
            sa.Column("remediation_id", sa.String(length=36), nullable=False),
            sa.Column("evidence_id", sa.String(length=36), nullable=False),
            sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("recorded_by", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["case_id"], ["campaigns.id"]),
            sa.ForeignKeyConstraint(["remediation_id"], ["remediation_items.id"]),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for name, column in (
            ("ix_remediation_verification_evidence_tenant_id", "tenant_id"),
            ("ix_remediation_verification_evidence_case_id", "case_id"),
            ("ix_remediation_verification_evidence_remediation_id", "remediation_id"),
            ("ix_remediation_verification_evidence_evidence_id", "evidence_id"),
            ("ix_remediation_verification_evidence_manifest_sha256", "manifest_sha256"),
        ):
            op.create_index(name, "remediation_verification_evidence", [column])

    if "approval_delegations" not in inspector.get_table_names():
        op.create_table(
            "approval_delegations",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("campaign_id", sa.String(length=36), nullable=True),
            sa.Column("delegator_username", sa.String(length=128), nullable=False),
            sa.Column("delegate_username", sa.String(length=128), nullable=False),
            sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("created_by", sa.String(length=128), nullable=False),
            sa.Column("revoked_by", sa.String(length=128), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for name, column in (
            ("ix_approval_delegations_tenant_id", "tenant_id"),
            ("ix_approval_delegations_campaign_id", "campaign_id"),
            ("ix_approval_delegations_delegator_username", "delegator_username"),
            ("ix_approval_delegations_delegate_username", "delegate_username"),
            ("ix_approval_delegations_starts_at", "starts_at"),
            ("ix_approval_delegations_expires_at", "expires_at"),
            ("ix_approval_delegations_status", "status"),
        ):
            op.create_index(name, "approval_delegations", [column])

    if "case_decision_events" not in inspector.get_table_names():
        op.create_table(
            "case_decision_events",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("case_id", sa.String(length=36), nullable=False),
            sa.Column("resource_type", sa.String(length=64), nullable=False),
            sa.Column("resource_id", sa.String(length=36), nullable=False),
            sa.Column("decision_type", sa.String(length=96), nullable=False),
            sa.Column("actor", sa.String(length=128), nullable=False),
            sa.Column("previous_state", sa.String(length=64), nullable=True),
            sa.Column("new_state", sa.String(length=64), nullable=True),
            sa.Column("reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("previous_digest", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("digest", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["case_id"], ["campaigns.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for name, column in (
            ("ix_case_decision_events_tenant_id", "tenant_id"),
            ("ix_case_decision_events_case_id", "case_id"),
            ("ix_case_decision_events_resource_type", "resource_type"),
            ("ix_case_decision_events_resource_id", "resource_id"),
            ("ix_case_decision_events_decision_type", "decision_type"),
            ("ix_case_decision_events_digest", "digest"),
        ):
            op.create_index(name, "case_decision_events", [column])


def downgrade() -> None:
    """Remove only phase-4 compliance tables and delegation columns."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table_name in ("case_decision_events", "approval_delegations", "remediation_verification_evidence"):
        if table_name in inspector.get_table_names():
            op.drop_table(table_name)

    risk_indexes = {index["name"] for index in inspector.get_indexes("risk_acceptances")}
    if "ix_risk_acceptances_delegation_id" in risk_indexes:
        op.drop_index("ix_risk_acceptances_delegation_id", table_name="risk_acceptances")
    risk_columns = {column["name"] for column in inspector.get_columns("risk_acceptances")}
    with op.batch_alter_table("risk_acceptances") as batch:
        for column in ("delegated_from", "delegation_id"):
            if column in risk_columns:
                batch.drop_column(column)
