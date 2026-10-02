"""delegation grants

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-02 00:00:00.000000

Adds ``delegation_grants`` — per-run, time-boxed delegations of a
permission subset from a user to an agent. Purely additive: no existing
table or column changes.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _json_type() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=False)
    op.create_table(
        "delegation_grants",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "tenant_id", uuid, sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "application_id",
            uuid,
            sa.ForeignKey("applications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id", uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "agent_id", uuid, sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("permissions", _json_type(), nullable=False),
        sa.Column("purpose", sa.String(1024), nullable=True),
        sa.Column("issued_by", sa.String(255), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_delegation_grants_tenant_agent", "delegation_grants", ["tenant_id", "agent_id"]
    )
    op.create_index(
        "ix_delegation_grants_tenant_user", "delegation_grants", ["tenant_id", "user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_delegation_grants_tenant_user", table_name="delegation_grants")
    op.drop_index("ix_delegation_grants_tenant_agent", table_name="delegation_grants")
    op.drop_table("delegation_grants")
