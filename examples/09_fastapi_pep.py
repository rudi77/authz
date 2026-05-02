"""FastAPI integration: protect a route with the AuthzClient as a PEP.

Spins up a tiny FastAPI app whose ``/contracts/{id}/review`` endpoint is
gated behind a permission check. The check runs against an in-process
AuthZ service driven by FastAPI's TestClient so the example needs no
external infrastructure.

The pattern translates one-to-one to a real deployment: replace the
TestClient with a real ``AuthzClient(base_url=...)`` and the rest of
your handler stays unchanged.

Run with::

    python examples/09_fastapi_pep.py
"""

from __future__ import annotations

import tempfile

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.testclient import TestClient

from authz_sdk import AuthzAdminClient, AuthzClient, PermissionDeniedError, Subject
from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine


def bootstrap_authz_service():
    """Build the AuthZ service in-process and seed a tenant + role + user."""
    db_path = tempfile.mkstemp(prefix="authz-example-", suffix=".db")[1]
    override_settings(
        Settings(
            database_url=f"sqlite+pysqlite:///{db_path}",
            api_keys=("dev-key",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
        )
    )
    reset_engine()

    from authz_service.main import create_app

    service_client = TestClient(create_app())

    with AuthzAdminClient("http://test", api_key="dev-key", http_client=service_client) as admin:
        tenant = admin.create_tenant(slug="acme", name="ACME")
        app = admin.create_application(slug="contracts", name="Contracts")
        admin.create_permission(app.id, name="contracts.review")
        admin.create_permission(app.id, name="contracts.delete")
        admin.upsert_role_with_permissions(
            app.id, name="reviewer", permissions=["contracts.review"]
        )
        admin.map_tenant_external(
            tenant.id, provider="generic_oidc",
            issuer="https://idp.example", external_tenant_id="acme",
        )

    return service_client, tenant.id, app.slug


def build_app(authz: AuthzClient, *, tenant_id: str, application_id: str) -> FastAPI:
    api = FastAPI()

    def current_user(x_user_id: str = Header(...)) -> str:
        # Real apps validate a JWT here; we trust a header for the demo.
        return x_user_id

    def require_permission(resource: str, action: str):
        def dependency(user_id: str = Depends(current_user)):
            try:
                authz.require(
                    tenant_id=tenant_id, application_id=application_id,
                    subject=Subject(type="user", user_id=user_id),
                    resource=resource, action=action,
                )
            except PermissionDeniedError as e:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={"reason": "missing_permission", "permission": e.permission},
                ) from e
        return dependency

    @api.post(
        "/contracts/{contract_id}/review",
        dependencies=[Depends(require_permission("contracts", "review"))],
    )
    def review(contract_id: str) -> dict:
        return {"contract_id": contract_id, "status": "reviewed"}

    @api.delete(
        "/contracts/{contract_id}",
        dependencies=[Depends(require_permission("contracts", "delete"))],
    )
    def delete(contract_id: str) -> dict:
        return {"contract_id": contract_id, "status": "deleted"}

    return api


def main() -> None:
    service_client, tenant_id, app_slug = bootstrap_authz_service()
    authz = AuthzClient("http://test", api_key="dev-key", http_client=service_client)

    # Provision Alice directly via the underlying SQLAlchemy store. In
    # production you'd typically use the invitation flow or your IdP's
    # SCIM provisioner; resolve-context only auto-provisions the user
    # row, never the membership.
    from authz_service.config import get_settings
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url

    engine = create_engine_from_url(get_settings().database_url)
    store = SqlAlchemyStore(engine)
    user, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp.example",
        subject="alice", email="alice@acme.com", external_tenant_id="acme",
    )

    with AuthzAdminClient("http://test", api_key="dev-key", http_client=service_client) as admin:
        application = admin.get_application(app_slug)
        admin.create_membership(
            tenant_id=tenant_id, user_id=user.id, application_id=application.id,
            roles=["reviewer"],
        )

    api = build_app(authz, tenant_id=tenant_id, application_id=application.id)
    test_api = TestClient(api)

    print("POST   /contracts/c-1/review with X-User-Id=alice ->", end=" ")
    r = test_api.post("/contracts/c-1/review", headers={"X-User-Id": user.id})
    print(r.status_code, r.json())

    print("DELETE /contracts/c-1        with X-User-Id=alice ->", end=" ")
    r = test_api.delete("/contracts/c-1", headers={"X-User-Id": user.id})
    print(r.status_code, r.json())


if __name__ == "__main__":
    main()
