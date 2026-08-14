"""add enterprise identity lifecycle tables

Revision ID: 565df19a3ca6
Revises: 8f4c1d2a7b90
Create Date: 2026-08-14 02:12:27.334658
"""
from alembic import op
import sqlalchemy as sa

revision = '565df19a3ca6'
down_revision = '8f4c1d2a7b90'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add enterprise identity records to pre-existing Alembic deployments."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "service_accounts" not in tables:
        op.create_table(
            "service_accounts",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
            sa.Column("scopes", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_service_accounts_tenant_id", "service_accounts", ["tenant_id"])
        op.create_index("ix_service_accounts_name", "service_accounts", ["name"])
        op.create_index("ix_service_accounts_is_active", "service_accounts", ["is_active"])

    if "service_account_tokens" not in tables:
        op.create_table(
            "service_account_tokens",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("service_account_id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("token_version", sa.Integer(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["service_account_id"], ["service_accounts.id"]),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token_hash"),
        )
        op.create_index("ix_service_account_tokens_service_account_id", "service_account_tokens", ["service_account_id"])
        op.create_index("ix_service_account_tokens_tenant_id", "service_account_tokens", ["tenant_id"])
        op.create_index("ix_service_account_tokens_token_hash", "service_account_tokens", ["token_hash"])
        op.create_index("ix_service_account_tokens_expires_at", "service_account_tokens", ["expires_at"])

    if "auth_sessions" in tables:
        columns = {column["name"] for column in inspector.get_columns("auth_sessions")}
        if "mfa_verified_until" not in columns:
            with op.batch_alter_table("auth_sessions") as batch:
                batch.add_column(sa.Column("mfa_verified_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Reverse only the schema introduced by this revision."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "auth_sessions" in tables:
        columns = {column["name"] for column in inspector.get_columns("auth_sessions")}
        if "mfa_verified_until" in columns:
            with op.batch_alter_table("auth_sessions") as batch:
                batch.drop_column("mfa_verified_until")
    if "service_account_tokens" in tables:
        op.drop_table("service_account_tokens")
    if "service_accounts" in tables:
        op.drop_table("service_accounts")
