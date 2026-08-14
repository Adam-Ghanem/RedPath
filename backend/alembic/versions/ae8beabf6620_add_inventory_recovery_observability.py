"""add inventory recovery observability

Revision ID: ae8beabf6620
Revises: 121bc374fe8e
Create Date: 2026-08-14 02:31:06.736987
"""
import sqlalchemy as sa
from alembic import op

revision = 'ae8beabf6620'
down_revision = '121bc374fe8e'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add bounded recovery metadata to discovery jobs when missing."""
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("discovery_jobs")}
    with op.batch_alter_table("discovery_jobs") as batch:
        if "duration_ms" not in columns:
            batch.add_column(sa.Column("duration_ms", sa.Integer(), nullable=True))
        if "recovery_count" not in columns:
            batch.add_column(sa.Column("recovery_count", sa.Integer(), nullable=False, server_default="0"))
        if "recovered_at" not in columns:
            batch.add_column(sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Remove only recovery metadata introduced by this revision."""
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("discovery_jobs")}
    with op.batch_alter_table("discovery_jobs") as batch:
        for column in ("recovered_at", "recovery_count", "duration_ms"):
            if column in columns:
                batch.drop_column(column)
