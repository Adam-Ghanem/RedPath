"""add case evidence custody events

Revision ID: 3c5e973700b9
Revises: 565df19a3ca6
Create Date: 2026-08-14 02:20:05.455207
"""
import sqlalchemy as sa
from alembic import op

revision = '3c5e973700b9'
down_revision = '565df19a3ca6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the tenant-scoped evidence custody history table when absent."""
    bind = op.get_bind()
    if "evidence_custody_events" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "evidence_custody_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["campaigns.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_custody_events_tenant_id", "evidence_custody_events", ["tenant_id"])
    op.create_index("ix_evidence_custody_events_case_id", "evidence_custody_events", ["case_id"])
    op.create_index("ix_evidence_custody_events_evidence_id", "evidence_custody_events", ["evidence_id"])
    op.create_index("ix_evidence_custody_events_decision", "evidence_custody_events", ["decision"])


def downgrade() -> None:
    """Remove only the custody history introduced by this revision."""
    bind = op.get_bind()
    if "evidence_custody_events" in sa.inspect(bind).get_table_names():
        op.drop_table("evidence_custody_events")
