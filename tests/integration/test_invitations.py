"""Invitation flow: create, accept, expire, revoke."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

HEADERS = {"X-API-Key": "k1"}


@pytest.fixture()
def client(temp_db_url) -> TestClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("k1",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


def _seed(client: TestClient):
    tenant = client.post("/v1/tenants", json={"slug": "t", "name": "T"}, headers=HEADERS).json()
    app = client.post(
        "/v1/applications", json={"slug": "a", "name": "A"}, headers=HEADERS
    ).json()
    for p in ["docs.read"]:
        client.post(f"/v1/applications/{app['id']}/permissions", json={"name": p}, headers=HEADERS)
    role = client.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "reader", "scope": "application"},
        headers=HEADERS,
    ).json()
    client.put(
        f"/v1/roles/{role['id']}/permissions",
        json={"permissions": ["docs.read"]},
        headers=HEADERS,
    )
    return tenant, app


def test_create_and_accept_invitation_creates_membership(client: TestClient):
    tenant, app = _seed(client)
    invite = client.post(
        f"/v1/tenants/{tenant['id']}/invitations",
        json={
            "email": "alice@example.com",
            "application_id": app["id"],
            "roles": ["reader"],
        },
        headers=HEADERS,
    ).json()
    assert invite["status"] == "pending"
    token = invite["token"]
    assert token

    response = client.post(
        f"/v1/invitations/{token}/accept",
        json={
            "provider": "azure_entra",
            "issuer": "https://login.example",
            "subject": "alice-oid",
            "email": "alice@example.com",
        },
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"

    # Verify membership exists by hitting authorize.
    from authz_service.config import get_settings
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url

    store = SqlAlchemyStore(create_engine_from_url(get_settings().database_url))
    user = store.find_user_by_external_identity(
        "azure_entra", "https://login.example", "alice-oid"
    )
    assert user is not None
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": user.id},
            "resource": "docs",
            "action": "read",
        },
        headers=HEADERS,
    ).json()
    assert response["allowed"] is True


def test_invalid_token_rejected(client: TestClient):
    tenant, app = _seed(client)
    response = client.post(
        "/v1/invitations/not-a-real-token/accept",
        json={
            "provider": "azure_entra",
            "issuer": "https://login.example",
            "subject": "x",
        },
        headers=HEADERS,
    )
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "invalid_token"


def test_expired_invitation_rejected(client: TestClient, temp_db_url):
    from authz_service.config import get_settings
    from authzkit.security.invitations import InvitationService
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url

    tenant, app = _seed(client)
    store = SqlAlchemyStore(create_engine_from_url(get_settings().database_url))
    invitations = InvitationService(store)
    token = invitations.create(
        tenant_id=tenant["id"],
        application_id=app["id"],
        email="bob@example.com",
        roles=["reader"],
        ttl=timedelta(seconds=-1),
    )
    response = client.post(
        f"/v1/invitations/{token.plaintext}/accept",
        json={
            "provider": "azure_entra",
            "issuer": "https://login.example",
            "subject": "bob",
        },
        headers=HEADERS,
    )
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "invitation_expired"


def test_revoked_invitation_rejected(client: TestClient):
    tenant, app = _seed(client)
    invite = client.post(
        f"/v1/tenants/{tenant['id']}/invitations",
        json={"email": "carol@example.com", "roles": []},
        headers=HEADERS,
    ).json()
    response = client.delete(
        f"/v1/invitations/{invite['id']}",
        headers=HEADERS,
    )
    assert response.status_code == 204
    response = client.post(
        f"/v1/invitations/{invite['token']}/accept",
        json={
            "provider": "oidc",
            "issuer": "https://x",
            "subject": "carol",
        },
        headers=HEADERS,
    )
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "invitation_not_pending"
