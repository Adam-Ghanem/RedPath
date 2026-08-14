"""Add discovery job reliability state and inventory lookup indexes.

Revision ID: c14f9b72d6e1
Revises: 7c9d2a4e1f6b
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "c14f9b72d6e1"
down_revision = "7c9d2a4e1f6b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add bounded lease, checkpoint, retry, and result metadata idempotently."""
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("discovery_jobs")}
    with op.batch_alter_table("discovery_jobs") as batch:
        additions = (
            ("lease_owner", sa.Column("lease_owner", sa.String(length=128), nullable=True)),
            ("lease_expires_at", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True)),
            ("attempt_count", sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0")),
            ("retry_budget", sa.Column("retry_budget", sa.Integer(), nullable=False, server_default="2")),
            ("retry_class", sa.Column("retry_class", sa.String(length=32), nullable=False, server_default="none")),
            ("next_retry_at", sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True)),
            ("checkpoint_stage", sa.Column("checkpoint_stage", sa.String(length=64), nullable=True)),
            ("checkpoint_json", sa.Column("checkpoint_json", sa.JSON(), nullable=True)),
            ("result_compacted", sa.Column(
                "result_compacted", sa.Boolean(), nullable=False, server_default=sa.false()
            )),
            ("result_bytes", sa.Column("result_bytes", sa.Integer(), nullable=True)),
            ("last_error_code", sa.Column("last_error_code", sa.String(length=64), nullable=True)),
        )
        for name, column in additions:
            if name not in columns:
                batch.add_column(column)

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("discovery_jobs")}
    if "ix_discovery_jobs_tenant_status_lease" not in indexes:
        op.create_index(
            "ix_discovery_jobs_tenant_status_lease",
            "discovery_jobs",
            ["tenant_id", "status", "lease_expires_at"],
        )

    asset_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("assets")}
    if "ix_assets_tenant_ip" not in asset_indexes:
        op.create_index("ix_assets_tenant_ip", "assets", ["tenant_id", "ip"])
    if "ix_assets_tenant_last_seen" not in asset_indexes:
        op.create_index("ix_assets_tenant_last_seen", "assets", ["tenant_id", "last_seen_at"])


def downgrade() -> None:
    """Remove only reliability fields and indexes introduced by this revision."""
    bind = op.get_bind()
    for table_name, index_name in (
        ("assets", "ix_assets_tenant_last_seen"),
        ("assets", "ix_assets_tenant_ip"),
        ("discovery_jobs", "ix_discovery_jobs_tenant_status_lease"),
    ):
        indexes = {index["name"] for index in sa.inspect(bind).get_indexes(table_name)}
        if index_name in indexes:
            op.drop_index(index_name, table_name=table_name)

    columns = {column["name"] for column in sa.inspect(bind).get_columns("discovery_jobs")}
    with op.batch_alter_table("discovery_jobs") as batch:
        for name in (
            "last_error_code",
            "result_bytes",
            "result_compacted",
            "checkpoint_json",
            "checkpoint_stage",
            "next_retry_at",
            "retry_class",
            "retry_budget",
            "attempt_count",
            "lease_expires_at",
            "lease_owner",
        ):
            if name in columns:
                batch.drop_column(name)
