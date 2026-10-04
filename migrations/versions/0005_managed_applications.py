"""managed applications, declarative catalog and tenant state

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-04 00:00:00.000000

Additive columns for the declarative provisioning endpoints:

- ``applications.managed_by`` — the one caller allowed to change the
  application's permissions, roles, memberships and agents (``NULL`` =
  unmanaged, the previous behaviour).
- ``permissions.deprecated`` / ``permissions.critical`` — catalog flags;
  deprecated permissions no longer count in decisions.
- ``roles.agent_id`` — marks the internal per-agent role that carries a
  provisioned agent's permissions.
- ``agents.display_name`` and a unique ``(tenant_id, application_id, name)``
  index so agents can be referenced by name. Fails if duplicate agent names
  already exist within one tenant and application; rename those first.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=False)
    op.add_column("applications", sa.Column("managed_by", sa.String(255), nullable=True))
    op.add_column(
        "permissions",
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "permissions",
        sa.Column("critical", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    with op.batch_alter_table("roles") as batch:
        batch.add_column(sa.Column("agent_id", uuid, nullable=True))
        batch.create_foreign_key(
            "fk_roles_agent_id_agents", "agents", ["agent_id"], ["id"], ondelete="CASCADE"
        )
    op.add_column("agents", sa.Column("display_name", sa.String(255), nullable=True))
    op.create_index(
        "uq_agents_tenant_application_name",
        "agents",
        ["tenant_id", "application_id", "name"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_agents_tenant_application_name", table_name="agents")
    op.drop_column("agents", "display_name")
    with op.batch_alter_table("roles") as batch:
        batch.drop_constraint("fk_roles_agent_id_agents", type_="foreignkey")
        batch.drop_column("agent_id")
    op.drop_column("permissions", "critical")
    op.drop_column("permissions", "deprecated")
    op.drop_column("applications", "managed_by")
