"""End-to-end recipe: validate a JWT, resolve context, enforce authorization.

This is the integration shape an application uses in production:

    1. Receive an HTTP request with ``Authorization: Bearer <jwt>``.
    2. Validate signature + standard claims against the IdP's JWKS.
    3. Normalize the verified claims into an IdentityPrincipal.
    4. Send the principal to the AuthZ service via /v1/resolve-context.
    5. Use the returned UserContext for permission checks via /v1/authorize.

The JWT validation step is **on the application side**, not inside the
AuthZ service. The service trusts that the caller has already verified the
token and only consumes the structured claims (spec §2.1).

Run after starting the service::

    docker compose up -d
    AUTHZ_BASE_URL=http://localhost:8080 AUTHZ_API_KEY=dev-key \\
        python examples/jwt_resolve_recipe.py
"""

from __future__ import annotations

import os

from authzkit.identity import JWTValidator, JWTValidatorConfig
from authzkit.identity.base import IdentityPrincipal
from authz_sdk import AuthzAdminClient, AuthzClient, Subject


def configure_validators() -> JWTValidator:
    """Configure validators for one or more upstream IdPs.

    Real applications: pull the issuer URL from your config (Entra tenant id
    is part of the issuer URL, Cognito user-pool id is in the issuer URL).
    The audience is your app's client_id / app-id.
    """
    return JWTValidator(
        configs=[
            JWTValidatorConfig(
                issuer="https://login.microsoftonline.com/<tenant_id>/v2.0",
                audience="api://<your-app-id>",
            ),
            JWTValidatorConfig(
                issuer=(
                    "https://cognito-idp.<region>.amazonaws.com/<user-pool-id>"
                ),
                audience="<cognito-client-id>",
            ),
        ]
    )


def authenticate_request(authorization_header: str, validator: JWTValidator) -> IdentityPrincipal:
    """Step 2 + 3: validate the bearer token and normalize its claims."""
    if not authorization_header.lower().startswith("bearer "):
        raise PermissionError("missing bearer token")
    token = authorization_header.split(None, 1)[1].strip()
    # ``provider`` should match the configured issuer in your AuthZ tenant
    # mapping. Pick it based on token's iss claim or your routing logic.
    return validator.validate_to_principal(token, provider="azure_entra")


def authorize_request(
    principal: IdentityPrincipal,
    *,
    application_slug: str,
    resource: str,
    action: str,
) -> bool:
    """Steps 4 + 5: resolve UserContext and enforce a permission check."""
    base = os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
    api_key = os.environ.get("AUTHZ_API_KEY", "dev-key")
    with AuthzClient(base, api_key=api_key, cache_ttl_seconds=300) as authz:
        ctx = authz.resolve_context(
            application_id=application_slug,
            provider=principal.provider,
            issuer=principal.issuer,
            subject=principal.subject,
            email=principal.email,
            external_tenant_id=principal.external_tenant_id,
            claims=dict(principal.claims),
        )
        return authz.authorize(
            tenant_id=ctx.tenant_id,
            application_id=ctx.application_id,
            subject=Subject(type="user", user_id=ctx.user_id),
            resource=resource,
            action=action,
        )


def demo_offline() -> None:
    """A self-contained demo using the in-memory store; doesn't need an IdP.

    Skips JWT validation and shows what the integration looks like once the
    principal is in hand. Real apps replace ``fake_principal`` with the
    output of ``authenticate_request(...)``.
    """
    fake_principal = IdentityPrincipal(
        provider="azure_entra",
        issuer="https://login.example/v2",
        subject="alice-oid",
        email="alice@acme.com",
        external_tenant_id="ext-acme",
        claims={"oid": "alice-oid", "tid": "ext-acme"},
    )

    base = os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
    api_key = os.environ.get("AUTHZ_API_KEY", "dev-key")
    with AuthzAdminClient(base, api_key=api_key) as admin:
        try:
            tenant = admin.get_tenant("acme")
        except Exception:
            tenant = admin.create_tenant(slug="acme", name="ACME")
        try:
            app = admin.get_application("contract-ai")
        except Exception:
            app = admin.create_application(slug="contract-ai", name="Contract AI")
        admin.create_permission(app.id, name="contracts.read")
        admin.upsert_role_with_permissions(
            app.id, name="reader", permissions=["contracts.read"]
        )
        admin.map_tenant_external(
            tenant.id,
            provider=fake_principal.provider,
            issuer=fake_principal.issuer,
            external_tenant_id=fake_principal.external_tenant_id or "",
        )

    allowed = authorize_request(
        fake_principal,
        application_slug="contract-ai",
        resource="contracts",
        action="read",
    )
    print(f"contracts.read allowed: {allowed}")


if __name__ == "__main__":
    demo_offline()
