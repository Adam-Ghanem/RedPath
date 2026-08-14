"""add case workflow governance columns

Revision ID: 935b0b17b45c
Revises: 3c5e973700b9
Create Date: 2026-08-14 02:22:45.164460
"""
from alembic import op
import sqlalchemy as sa

revision = '935b0b17b45c'
down_revision = '3c5e973700b9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add tenant-safe workflow metadata to existing operational records."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    evidence_columns = {column["name"] for column in inspector.get_columns("evidence_items")}
    with op.batch_alter_table("evidence_items") as batch:
        if "custody_status" not in evidence_columns:
            batch.add_column(sa.Column("custody_status", sa.String(length=32), nullable=False, server_default="unverified"))
        if "custody_verified_by" not in evidence_columns:
            batch.add_column(sa.Column("custody_verified_by", sa.String(length=128), nullable=True))
        if "custody_verified_at" not in evidence_columns:
            batch.add_column(sa.Column("custody_verified_at", sa.DateTime(timezone=True), nullable=True))
        if "custody_verification_sha256" not in evidence_columns:
            batch.add_column(sa.Column("custody_verification_sha256", sa.String(length=64), nullable=True))
    if "custody_status" not in evidence_columns:
        op.create_index("ix_evidence_items_custody_status", "evidence_items", ["custody_status"])

    remediation_columns = {column["name"] for column in inspector.get_columns("remediation_items")}
    with op.batch_alter_table("remediation_items") as batch:
        if "assigned_to" not in remediation_columns:
            batch.add_column(sa.Column("assigned_to", sa.String(length=128), nullable=True))
        if "verification_status" not in remediation_columns:
            batch.add_column(sa.Column("verification_status", sa.String(length=32), nullable=False, server_default="unverified"))
        if "verified_by" not in remediation_columns:
            batch.add_column(sa.Column("verified_by", sa.String(length=128), nullable=True))
        if "verified_at" not in remediation_columns:
            batch.add_column(sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    if "assigned_to" not in remediation_columns:
        op.create_index("ix_remediation_items_assigned_to", "remediation_items", ["assigned_to"])
    if "verification_status" not in remediation_columns:
        op.create_index("ix_remediation_items_verification_status", "remediation_items", ["verification_status"])

    acceptance_columns = {column["name"] for column in inspector.get_columns("risk_acceptances")}
    with op.batch_alter_table("risk_acceptances") as batch:
        if "approval_status" not in acceptance_columns:
            batch.add_column(sa.Column("approval_status", sa.String(length=32), nullable=False, server_default="approved"))
        if "approved_by" not in acceptance_columns:
            batch.add_column(sa.Column("approved_by", sa.String(length=128), nullable=True))
        if "approved_at" not in acceptance_columns:
            batch.add_column(sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
        if "revoked_by" not in acceptance_columns:
            batch.add_column(sa.Column("revoked_by", sa.String(length=128), nullable=True))
        if "revoked_at" not in acceptance_columns:
            batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    if "approval_status" not in acceptance_columns:
        op.create_index("ix_risk_acceptances_approval_status", "risk_acceptances", ["approval_status"])


def downgrade() -> None:
    """Remove only columns introduced by this revision."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    evidence_columns = {column["name"] for column in inspector.get_columns("evidence_items")}
    evidence_indexes = {index["name"] for index in inspector.get_indexes("evidence_items")}
    if "ix_evidence_items_custody_status" in evidence_indexes:
        op.drop_index("ix_evidence_items_custody_status", table_name="evidence_items")
    with op.batch_alter_table("evidence_items") as batch:
        for column in ("custody_verification_sha256", "custody_verified_at", "custody_verified_by", "custody_status"):
            if column in evidence_columns:
                batch.drop_column(column)
    remediation_columns = {column["name"] for column in inspector.get_columns("remediation_items")}
    remediation_indexes = {index["name"] for index in inspector.get_indexes("remediation_items")}
    if "ix_remediation_items_assigned_to" in remediation_indexes:
        op.drop_index("ix_remediation_items_assigned_to", table_name="remediation_items")
    if "ix_remediation_items_verification_status" in remediation_indexes:
        op.drop_index("ix_remediation_items_verification_status", table_name="remediation_items")
    with op.batch_alter_table("remediation_items") as batch:
        for column in ("verified_at", "verified_by", "verification_status", "assigned_to"):
            if column in remediation_columns:
                batch.drop_column(column)
    acceptance_columns = {column["name"] for column in inspector.get_columns("risk_acceptances")}
    acceptance_indexes = {index["name"] for index in inspector.get_indexes("risk_acceptances")}
    if "ix_risk_acceptances_approval_status" in acceptance_indexes:
        op.drop_index("ix_risk_acceptances_approval_status", table_name="risk_acceptances")
    with op.batch_alter_table("risk_acceptances") as batch:
        for column in ("revoked_at", "revoked_by", "approved_at", "approved_by", "approval_status"):
            if column in acceptance_columns:
                batch.drop_column(column)
