"""oauth clients, signing keys, admin sessions

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-27 00:00:00.000000

Adds the schema needed for the OAuth 2.0 roles:

- ``oauth_clients``         — client_credentials clients (RFC 6749 §4.4)
- ``oauth_signing_keys``    — RSA signing keys for issued JWTs
- ``admin_sessions``        — server-side admin browser sessions
- ``admin_login_attempts``  — in-flight PKCE / state / nonce store

JSON columns are JSONB on Postgres, JSON on SQLite (see authzkit.storage.orm).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _json_type() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("client_id", sa.String(64), nullable=False, unique=True),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scopes", sa.String(512), nullable=False, server_default="runtime"),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_oauth_clients_status", "oauth_clients", ["status"])

    op.create_table(
        "oauth_signing_keys",
        sa.Column("kid", sa.String(64), primary_key=True),
        sa.Column("alg", sa.String(16), nullable=False, server_default="RS256"),
        sa.Column("public_jwk", _json_type(), nullable=False),
        sa.Column("private_pem", sa.String(8192), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_oauth_signing_keys_status", "oauth_signing_keys", ["status"]
    )
    # Partial unique index: at most one row may carry status='active'. The
    # second concurrent INSERT then fails at the DB level instead of
    # silently producing two active keys. SQLite supports partial indexes
    # since 3.8; Postgres natively. Alembic emits CREATE UNIQUE INDEX
    # ... WHERE status='active' which both engines accept.
    op.create_index(
        "uq_oauth_signing_keys_active",
        "oauth_signing_keys",
        ["status"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "admin_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("scopes", sa.String(512), nullable=False, server_default="admin"),
        sa.Column("raw_claims", _json_type(), nullable=False),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_admin_sessions_expires", "admin_sessions", ["expires_at"])

    op.create_table(
        "admin_login_attempts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("state", sa.String(64), nullable=False, unique=True),
        sa.Column("code_verifier", sa.String(255), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column(
            "return_to", sa.String(512), nullable=False, server_default="/admin/"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_admin_login_attempts_expires", "admin_login_attempts", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_admin_login_attempts_expires", table_name="admin_login_attempts")
    op.drop_table("admin_login_attempts")
    op.drop_index("ix_admin_sessions_expires", table_name="admin_sessions")
    op.drop_table("admin_sessions")
    op.drop_index("uq_oauth_signing_keys_active", table_name="oauth_signing_keys")
    op.drop_index("ix_oauth_signing_keys_status", table_name="oauth_signing_keys")
    op.drop_table("oauth_signing_keys")
    op.drop_index("ix_oauth_clients_status", table_name="oauth_clients")
    op.drop_table("oauth_clients")
