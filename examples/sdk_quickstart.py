"""SDK quickstart against a running AuthZ service.

Assumes the service is reachable at ``$AUTHZ_BASE_URL`` (default
``http://localhost:8080``) and an API key in ``$AUTHZ_API_KEY``.

This script seeds a tenant, application, role, and user via the management
APIs, then runs an authorize check both as a user and as an agent.
"""

from __future__ import annotations

import os

from authz_sdk import AuthzClient, BulkCheck, Subject
from authz_sdk.agent_session import start_agent_session


BASE_URL = os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
API_KEY = os.environ.get("AUTHZ_API_KEY", "dev-key")


def main() -> None:
    with AuthzClient(BASE_URL, api_key=API_KEY, cache_ttl_seconds=300) as client:
        # Note: AuthzClient is a thin REST wrapper; admin API calls below use
        # the underlying httpx client directly because the SDK's surface only
        # covers the runtime authorize endpoints.
        http = client._http
        tenant = http.post("/v1/tenants", json={"slug": "demo", "name": "Demo"}).json()
        app = http.post(
            "/v1/applications", json={"slug": "demo-app", "name": "Demo App"}
        ).json()
        for name in ["docs.read", "docs.write", "tools.email.send"]:
            http.post(
                f"/v1/applications/{app['id']}/permissions",
                json={"name": name},
            )
        role = http.post(
            f"/v1/applications/{app['id']}/roles",
            json={"name": "editor", "scope": "application"},
        ).json()
        http.put(
            f"/v1/roles/{role['id']}/permissions",
            json={"permissions": ["docs.read", "docs.write"]},
        )

        # Resolve context — auto-provisions the user.
        ctx = client.resolve_context(
            application_id=app["slug"],
            provider="generic_oidc",
            issuer="https://idp.example",
            subject="alice",
            email="alice@example.com",
        )
        # If the resolve-context call fails (no membership), create one then retry.
        # Skipped here for brevity; see the test suite for the full flow.
        print("Resolved context:", ctx)

        decisions = client.bulk_authorize(
            tenant_id=tenant["id"],
            application_id=app["id"],
            subject=Subject(type="user", user_id=ctx.user_id),
            checks=[
                BulkCheck("docs", "read"),
                BulkCheck("docs", "write"),
                BulkCheck("tools.email", "send"),
            ],
        )
        for d in decisions:
            mark = "ALLOW" if d.allowed else "DENY "
            print(f"  {mark} {d.resource}.{d.action} ({d.reason})")


if __name__ == "__main__":
    main()
