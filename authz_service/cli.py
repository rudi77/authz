"""``authz`` CLI for bootstrap, schema, and admin operations.

Three command groups:

- ``authz schema``   — create/upgrade DB schema (Alembic-backed)
- ``authz bootstrap``— seed a tenant + application + roles from a YAML/JSON spec
- ``authz inspect``  — quick read-only checks (health, decisions)

The CLI hits the AuthZ service over HTTP for admin work — same code path as
external automation. Schema commands run locally because Alembic needs DB
URL access.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is optional
    yaml = None  # type: ignore[assignment]

from authz_sdk.admin import AuthzAdminClient


def _load_spec(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"spec file not found: {path}")
    text = p.read_text()
    if path.endswith((".yaml", ".yml")):
        if yaml is None:
            raise SystemExit("install pyyaml to use YAML specs (pip install pyyaml)")
        return yaml.safe_load(text)
    return json.loads(text)


def _admin_client(args) -> AuthzAdminClient:
    base = args.base_url or os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
    api_key = args.api_key or os.environ.get("AUTHZ_API_KEY")
    return AuthzAdminClient(base, api_key=api_key)


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------


def cmd_schema_upgrade(args: argparse.Namespace) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(args.alembic_ini or "alembic.ini")
    if args.database_url:
        cfg.set_main_option("sqlalchemy.url", args.database_url)
    command.upgrade(cfg, args.revision)
    print(f"schema upgraded to {args.revision}")


def cmd_schema_current(args: argparse.Namespace) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(args.alembic_ini or "alembic.ini")
    if args.database_url:
        cfg.set_main_option("sqlalchemy.url", args.database_url)
    command.current(cfg, verbose=True)


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


def cmd_bootstrap(args: argparse.Namespace) -> None:
    """Seed a tenant + application + roles from a YAML/JSON spec.

    Spec shape::

        tenant:
          slug: acme
          name: ACME
          mappings:
            - provider: azure_entra
              issuer: https://login.microsoftonline.com/x/v2.0
              external_tenant_id: ext-acme
          feature_flags:
            github_mcp_enabled: true
        application:
          slug: contract-ai
          name: Contract AI
          permissions:
            - contracts.read
            - contracts.review
            - mcp.github.read_repo
          roles:
            - name: legal_reviewer
              scope: application
              permissions: [contracts.read, contracts.review]
            - name: contract_analysis_agent
              scope: agent
              permissions: [contracts.read, mcp.github.read_repo]
        agents:
          - name: Contract Analyzer
            role: contract_analysis_agent
        memberships:
          - user_id: 00000000-0000-0000-0000-000000000001
            roles: [legal_reviewer]
    """
    spec = _load_spec(args.spec)
    with _admin_client(args) as client:
        tenant_spec = spec.get("tenant", {})
        app_spec = spec.get("application", {})
        if not tenant_spec or not app_spec:
            raise SystemExit("spec must contain 'tenant' and 'application' sections")

        # Tenant — find-or-create.
        tenant = None
        try:
            tenant = client.get_tenant(tenant_spec["slug"])
            print(f"tenant {tenant.slug} already exists ({tenant.id})")
        except Exception:
            tenant = client.create_tenant(
                slug=tenant_spec["slug"],
                name=tenant_spec.get("name", tenant_spec["slug"]),
            )
            print(f"created tenant {tenant.slug} ({tenant.id})")

        # External tenant mappings
        for mapping in tenant_spec.get("mappings", []):
            try:
                client.map_tenant_external(
                    tenant.id,
                    provider=mapping["provider"],
                    issuer=mapping["issuer"],
                    external_tenant_id=mapping["external_tenant_id"],
                )
                print(f"  mapped {mapping['provider']} ext={mapping['external_tenant_id']}")
            except Exception as e:
                print(f"  skip mapping {mapping}: {e}")

        # Application — find-or-create
        try:
            application = client.get_application(app_spec["slug"])
            print(f"application {application.slug} already exists ({application.id})")
        except Exception:
            application = client.create_application(
                slug=app_spec["slug"],
                name=app_spec.get("name", app_spec["slug"]),
            )
            print(f"created application {application.slug} ({application.id})")

        # Permissions — create idempotently.
        existing_perms = {p.name for p in client.list_permissions(application.id)}
        for name in app_spec.get("permissions", []):
            if name in existing_perms:
                continue
            client.create_permission(application.id, name=name)
            print(f"  + permission {name}")

        # Roles — upsert with permission set replaced each time (declarative).
        for role_spec in app_spec.get("roles", []):
            role = client.upsert_role_with_permissions(
                application.id,
                name=role_spec["name"],
                scope=role_spec.get("scope", "application"),
                permissions=list(role_spec.get("permissions") or []),
            )
            print(f"  role {role.name} ({len(role_spec.get('permissions') or [])} perms)")

        # Feature flags
        for key, value in (tenant_spec.get("feature_flags") or {}).items():
            client.set_feature_flag(tenant.id, key=key, value=value)
            print(f"  feature_flag {key}={value}")

        # Memberships
        for m in spec.get("memberships", []):
            membership = client.create_membership(
                tenant.id,
                user_id=m["user_id"],
                application_id=application.id,
                roles=m.get("roles") or [],
            )
            print(f"  membership user={m['user_id']} roles={m.get('roles')} ({membership.id})")

        # Agents
        for a in spec.get("agents", []):
            agent = client.create_agent(
                tenant.id,
                application.id,
                name=a["name"],
                role=a.get("role", ""),
            )
            roles = [a["role"]] if a.get("role") else []
            if roles:
                client.set_agent_roles(agent.id, roles)
            print(f"  agent {agent.name} ({agent.id}) roles={roles}")

        print("\nbootstrap complete")


# ---------------------------------------------------------------------------
# oauth — client + signing key management (runs locally, hits the DB directly)
# ---------------------------------------------------------------------------


def _local_store(args: argparse.Namespace):
    """Build a SqlAlchemyStore against the configured DB URL."""
    from authz_service.config import get_settings
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url

    url = args.database_url or os.environ.get(
        "AUTHZ_DATABASE_URL", get_settings().database_url
    )
    engine = create_engine_from_url(url)
    return SqlAlchemyStore(engine)


def cmd_oauth_client_create(args: argparse.Namespace) -> None:
    from authzkit.security.oauth_clients import OAuthClientService

    store = _local_store(args)
    service = OAuthClientService(store)
    scopes = [s for s in args.scopes.split(",") if s.strip()]
    credentials = service.issue(
        name=args.name, scopes=scopes, tenant_id=args.tenant_id
    )
    print(
        json.dumps(
            {
                "client_id": credentials.record.client_id,
                "client_secret": credentials.client_secret,
                "name": credentials.record.name,
                "scopes": list(credentials.record.scopes),
                "tenant_id": credentials.record.tenant_id,
            },
            indent=2,
        )
    )


def cmd_oauth_client_list(args: argparse.Namespace) -> None:
    from authzkit.security.oauth_clients import OAuthClientService

    store = _local_store(args)
    service = OAuthClientService(store)
    rows = [
        {
            "client_id": r.client_id,
            "name": r.name,
            "scopes": list(r.scopes),
            "tenant_id": r.tenant_id,
            "status": r.status,
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
        }
        for r in service.list_clients()
    ]
    print(json.dumps(rows, indent=2))


def cmd_oauth_client_revoke(args: argparse.Namespace) -> None:
    from authzkit.security.oauth_clients import OAuthClientService

    store = _local_store(args)
    service = OAuthClientService(store)
    if not service.revoke(args.client_id):
        raise SystemExit(f"client_id not found: {args.client_id}")
    print(f"revoked {args.client_id}")


def cmd_oauth_client_rotate(args: argparse.Namespace) -> None:
    from authzkit.security.oauth_clients import OAuthClientService

    store = _local_store(args)
    service = OAuthClientService(store)
    credentials = service.rotate_secret(args.client_id)
    if credentials is None:
        raise SystemExit(f"client_id not found: {args.client_id}")
    print(
        json.dumps(
            {
                "client_id": credentials.record.client_id,
                "client_secret": credentials.client_secret,
            },
            indent=2,
        )
    )


def cmd_oauth_key_generate(args: argparse.Namespace) -> None:
    """Generate a fresh RSA signing key and persist it as the active one."""
    from authzkit.security.signing_keys import SigningKeyService

    store = _local_store(args)
    service = SigningKeyService(store, dev_mode=True, database_url="sqlite+pysqlite:")
    # Force the generate path by leaving env_pem empty and pretending dev+sqlite
    # so the safety guard accepts persistence regardless of the actual DSN —
    # operators run this intentionally, the prod-DSN guard exists to prevent
    # *accidental* generation at boot.
    key = service._generate_and_persist()
    print(
        json.dumps(
            {"kid": key.kid, "alg": key.alg, "status": key.status}, indent=2
        )
    )


def cmd_oauth_key_rotate(args: argparse.Namespace) -> None:
    from authz_service.config import get_settings
    from authzkit.security.signing_keys import SigningKeyService

    settings = get_settings()
    store = _local_store(args)
    service = SigningKeyService(
        store,
        env_pem=settings.oauth_signing_key_pem,
        dev_mode=settings.dev_mode,
        database_url=settings.database_url,
    )
    key = service.rotate()
    print(
        json.dumps(
            {"kid": key.kid, "alg": key.alg, "status": key.status}, indent=2
        )
    )


def cmd_oauth_key_list(args: argparse.Namespace) -> None:
    from authzkit.security.signing_keys import SigningKeyService

    store = _local_store(args)
    service = SigningKeyService(store)
    rows = [
        {
            "kid": k.kid,
            "alg": k.alg,
            "status": k.status,
            "created_at": k.created_at.isoformat() if k.created_at else None,
        }
        for k in service.list_keys()
    ]
    print(json.dumps(rows, indent=2))


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


def cmd_inspect_health(args: argparse.Namespace) -> None:
    base = args.base_url or os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
    response = httpx.get(f"{base.rstrip('/')}/healthz", timeout=5.0)
    print(f"HTTP {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    sys.exit(0 if response.status_code < 400 else 1)


def cmd_inspect_decision(args: argparse.Namespace) -> None:
    from authz_sdk.client import AuthzClient, Subject

    base = args.base_url or os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
    api_key = args.api_key or os.environ.get("AUTHZ_API_KEY")
    with AuthzClient(base, api_key=api_key) as client:
        subject = Subject(
            type=args.subject_type, user_id=args.user_id, agent_id=args.agent_id
        )
        allowed = client.authorize(
            tenant_id=args.tenant_id,
            application_id=args.application_id,
            subject=subject,
            resource=args.resource,
            action=args.action,
        )
        print(f"{'ALLOW' if allowed else 'DENY '} {args.resource}.{args.action}")
        sys.exit(0 if allowed else 2)


# ---------------------------------------------------------------------------
# parser wiring
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="authz", description="AuthZ CLI")
    parser.add_argument("--base-url", help="Service base URL (env: AUTHZ_BASE_URL)")
    parser.add_argument("--api-key", help="Service API key (env: AUTHZ_API_KEY)")
    sub = parser.add_subparsers(dest="command", required=True)

    # schema
    schema = sub.add_parser("schema", help="Database schema operations")
    schema_sub = schema.add_subparsers(dest="schema_command", required=True)

    upgrade = schema_sub.add_parser("upgrade", help="Run alembic upgrade")
    upgrade.add_argument("--alembic-ini", default="alembic.ini")
    upgrade.add_argument("--database-url", help="Override DB URL (env: AUTHZ_DATABASE_URL)")
    upgrade.add_argument("--revision", default="head")
    upgrade.set_defaults(func=cmd_schema_upgrade)

    current = schema_sub.add_parser("current", help="Show current revision")
    current.add_argument("--alembic-ini", default="alembic.ini")
    current.add_argument("--database-url")
    current.set_defaults(func=cmd_schema_current)

    # bootstrap
    bootstrap = sub.add_parser(
        "bootstrap", help="Seed tenant + application + roles from a spec file"
    )
    bootstrap.add_argument("--spec", required=True, help="YAML or JSON spec file")
    bootstrap.set_defaults(func=cmd_bootstrap)

    # oauth
    oauth = sub.add_parser("oauth", help="OAuth client + signing-key management")
    oauth_sub = oauth.add_subparsers(dest="oauth_command", required=True)

    oc = oauth_sub.add_parser("client", help="client_credentials clients")
    oc_sub = oc.add_subparsers(dest="oauth_client_command", required=True)

    oc_create = oc_sub.add_parser("create", help="Issue a new OAuth client")
    oc_create.add_argument("--name", required=True)
    oc_create.add_argument(
        "--scopes", default="runtime", help="Comma-separated scopes (default: runtime)"
    )
    oc_create.add_argument("--tenant-id", default=None)
    oc_create.add_argument("--database-url")
    oc_create.set_defaults(func=cmd_oauth_client_create)

    oc_list = oc_sub.add_parser("list", help="List OAuth clients")
    oc_list.add_argument("--database-url")
    oc_list.set_defaults(func=cmd_oauth_client_list)

    oc_revoke = oc_sub.add_parser("revoke", help="Revoke an OAuth client")
    oc_revoke.add_argument("client_id")
    oc_revoke.add_argument("--database-url")
    oc_revoke.set_defaults(func=cmd_oauth_client_revoke)

    oc_rotate = oc_sub.add_parser("rotate", help="Rotate an OAuth client secret")
    oc_rotate.add_argument("client_id")
    oc_rotate.add_argument("--database-url")
    oc_rotate.set_defaults(func=cmd_oauth_client_rotate)

    sk = oauth_sub.add_parser("signing-key", help="JWT signing keys")
    sk_sub = sk.add_subparsers(dest="signing_key_command", required=True)

    sk_gen = sk_sub.add_parser("generate", help="Generate a new RSA-2048 signing key")
    sk_gen.add_argument("--database-url")
    sk_gen.set_defaults(func=cmd_oauth_key_generate)

    sk_rot = sk_sub.add_parser(
        "rotate", help="Rotate the active signing key (env-supplied keys: redeploy instead)"
    )
    sk_rot.add_argument("--database-url")
    sk_rot.set_defaults(func=cmd_oauth_key_rotate)

    sk_list = sk_sub.add_parser("list", help="List signing keys")
    sk_list.add_argument("--database-url")
    sk_list.set_defaults(func=cmd_oauth_key_list)

    # inspect
    inspect = sub.add_parser("inspect", help="Read-only checks")
    inspect_sub = inspect.add_subparsers(dest="inspect_command", required=True)

    health = inspect_sub.add_parser("health", help="Hit /healthz")
    health.set_defaults(func=cmd_inspect_health)

    decision = inspect_sub.add_parser("decision", help="One-shot authorize check")
    decision.add_argument("--tenant-id", required=True)
    decision.add_argument("--application-id", required=True)
    decision.add_argument("--subject-type", default="user", choices=["user", "agent"])
    decision.add_argument("--user-id")
    decision.add_argument("--agent-id")
    decision.add_argument("--resource", required=True)
    decision.add_argument("--action", required=True)
    decision.set_defaults(func=cmd_inspect_decision)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
