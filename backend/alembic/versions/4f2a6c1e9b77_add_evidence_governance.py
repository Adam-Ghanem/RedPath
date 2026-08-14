"""add evidence governance interfaces

Revision ID: 4f2a6c1e9b77
Revises: c14f9b72d6e1
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "4f2a6c1e9b77"
down_revision = "c14f9b72d6e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add tenant-scoped legal-hold and approval metadata without storing evidence content."""
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "evidence_legal_holds" not in tables:
        op.create_table(
            "evidence_legal_holds",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("evidence_id", sa.String(length=36), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("placed_by", sa.String(length=128), nullable=True),
            sa.Column("placed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("released_by", sa.String(length=128), nullable=True),
            sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_evidence_legal_holds_tenant_id", "evidence_legal_holds", ["tenant_id"])
        op.create_index("ix_evidence_legal_holds_evidence_id", "evidence_legal_holds", ["evidence_id"])
        op.create_index("ix_evidence_legal_holds_active", "evidence_legal_holds", ["active"])
    if "evidence_retention_decisions" not in tables:
        op.create_table(
            "evidence_retention_decisions",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("evidence_id", sa.String(length=36), nullable=False),
            sa.Column("decision", sa.String(length=32), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("actor", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_evidence_retention_decisions_tenant_id", "evidence_retention_decisions", ["tenant_id"])
        op.create_index("ix_evidence_retention_decisions_evidence_id", "evidence_retention_decisions", ["evidence_id"])
        op.create_index("ix_evidence_retention_decisions_decision", "evidence_retention_decisions", ["decision"])
    if "evidence_deletion_requests" not in tables:
        op.create_table(
            "evidence_deletion_requests",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("evidence_id", sa.String(length=36), nullable=False),
            sa.Column("state", sa.String(length=32), nullable=False, server_default="requested"),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("requested_by", sa.String(length=128), nullable=False),
            sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("decided_by", sa.String(length=128), nullable=True),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("decision_note", sa.Text(), nullable=False, server_default=""),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_evidence_deletion_requests_tenant_id", "evidence_deletion_requests", ["tenant_id"])
        op.create_index("ix_evidence_deletion_requests_evidence_id", "evidence_deletion_requests", ["evidence_id"])
        op.create_index("ix_evidence_deletion_requests_state", "evidence_deletion_requests", ["state"])


def downgrade() -> None:
    """Remove only governance metadata introduced by this revision."""
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for table_name in (
        "evidence_deletion_requests",
        "evidence_retention_decisions",
        "evidence_legal_holds",
    ):
        if table_name in tables:
            op.drop_table(table_name)
