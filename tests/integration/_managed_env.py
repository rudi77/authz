"""Shared setup for the declarative-provisioning tests (Z-2/Z-3/Z-4/Z-8).

The service runs with the OAuth Authorization Server on. A *management*
client (admin scope) creates the application through the catalog endpoint
and becomes its ``managed_by``; the bootstrap API key is the platform
operator (admin, but not the manager); a *runtime* client only decides.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

ISSUER = "https://authz.local"
ADMIN_KEY = "bootstrap-admin"
OPERATOR = {"X-API-Key": ADMIN_KEY}

CATALOG = {
    "name": "Digital Teammates",
    "permissions": [
        {"name": "runs.start", "description": "Start runs"},
        {"name": "tools.file_read.invoke"},
        {"name": "mcp.sap-prod.read"},
        {"name": "mcp.sap-prod.write", "critical": True},
    ],
    "default_roles": [
        {"name": "Operator", "description": "Runs things", "permissions": ["runs.start"]},
        {
            "name": "Approver",
            "permissions": ["runs.start", "mcp.sap-prod.read", "tools.file_read.invoke"],
        },
    ],
}


@dataclass
class ManagedEnv:
    client: TestClient
    manager: dict[str, str]
    manager_label: str
    runtime: dict[str, str]


def _token(client: TestClient, scopes: list[str]) -> tuple[str, dict[str, str]]:
    created = client.post(
        "/v1/oauth/clients", json={"name": "c", "scopes": scopes}, headers=OPERATOR
    ).json()
    raw = f"{created['client_id']}:{created['client_secret']}".encode()
    r = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")},
    )
    assert r.status_code == 200, r.text
    return created["client_id"], {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_env(temp_db_url: str, *, with_catalog: bool = True) -> ManagedEnv:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=(ADMIN_KEY,),
            log_level="WARNING",
            dev_mode=True,
            oauth_as_enabled=True,
            oauth_issuer=ISSUER,
            oauth_audience=ISSUER,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    client = TestClient(create_app())
    manager_id, manager = _token(client, ["admin"])
    _, runtime = _token(client, ["runtime"])
    env = ManagedEnv(client, manager, f"client:{manager_id}", runtime)
    if with_catalog:
        r = client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=manager)
        assert r.status_code == 200, r.text
    return env


def member(subject: str, roles: list[str], **extra) -> dict:
    return {
        "user_ref": {"provider": "dtm", "issuer": "urn:dtm:test", "subject": subject},
        "display_name": subject.title(),
        "email": f"{subject}@acme.test",
        "roles": roles,
        **extra,
    }


def user_ref(subject: str) -> dict:
    return {"provider": "dtm", "issuer": "urn:dtm:test", "subject": subject}
