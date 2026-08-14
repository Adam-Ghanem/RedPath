"""add pcap evidence lifecycle metadata

Revision ID: 22d614b2aac8
Revises: ae8beabf6620
Create Date: 2026-08-14 02:36:16.258808
"""
import sqlalchemy as sa
from alembic import op

revision = '22d614b2aac8'
down_revision = 'ae8beabf6620'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create tenant-scoped metadata-only PCAP lifecycle records when absent."""
    bind = op.get_bind()
    if "pcap_lifecycles" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "pcap_lifecycles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="retained"),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("parse_error", sa.String(length=255), nullable=True),
        sa.Column("storage_backend", sa.String(length=32), nullable=False, server_default="metadata-only"),
        sa.Column("storage_locator", sa.String(length=16), nullable=False, server_default="none"),
        sa.Column("raw_bytes_retained", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("stored_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"]),
        sa.ForeignKeyConstraint(["analysis_id"], ["pcap_analyses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pcap_lifecycles_tenant_id", "pcap_lifecycles", ["tenant_id"])
    op.create_index("ix_pcap_lifecycles_evidence_id", "pcap_lifecycles", ["evidence_id"])
    op.create_index("ix_pcap_lifecycles_analysis_id", "pcap_lifecycles", ["analysis_id"])
    op.create_index("ix_pcap_lifecycles_state", "pcap_lifecycles", ["state"])
    op.create_index("ix_pcap_lifecycles_source_sha256", "pcap_lifecycles", ["source_sha256"])
    op.create_index("ix_pcap_lifecycles_retention_until", "pcap_lifecycles", ["retention_until"])
    op.create_index("ix_pcap_lifecycles_manifest_sha256", "pcap_lifecycles", ["manifest_sha256"])


def downgrade() -> None:
    """Remove only metadata lifecycle records introduced by this revision."""
    bind = op.get_bind()
    if "pcap_lifecycles" in sa.inspect(bind).get_table_names():
        op.drop_table("pcap_lifecycles")
