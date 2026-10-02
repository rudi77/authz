"""Delegation grants: issuance, narrowing, revocation, and non-regression."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

HEADERS = {"X-API-Key": "test-key"}


def _client(temp_db_url, **overrides) -> TestClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("test-key",),
            log_level="WARNING",
            audit_all_decisions=True,
            **overrides,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


@pytest.fixture()
def client(temp_db_url) -> TestClient:
    return _client(temp_db_url)


def _seed(client: TestClient) -> dict:
    """Alice (reader+reviewer+approver) and an agent (reader+reviewer+classifier).

    user ∩ agent = {contracts.read, contracts.review}
    """
    tenant = client.post("/v1/tenants", json={"slug": "acme", "name": "ACME"}, headers=HEADERS).json()
    app = client.post(
        "/v1/applications", json={"slug": "contracts", "name": "Contracts"}, headers=HEADERS
    ).json()
    for name in ["contracts.read", "contracts.review", "contracts.approve", "contracts.classify"]:
        client.post(f"/v1/applications/{app['id']}/permissions", json={"name": name}, headers=HEADERS)
    human = client.post(
        f"/v1/applications/{app['id']}/roles", json={"name": "lawyer"}, headers=HEADERS
    ).json()
    client.put(
        f"/v1/roles/{human['id']}/permissions",
        json={"permissions": ["contracts.read", "contracts.review", "contracts.approve"]},
        headers=HEADERS,
    )
    bot = client.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "analyzer", "scope": "agent"},
        headers=HEADERS,
    ).json()
    client.put(
        f"/v1/roles/{bot['id']}/permissions",
        json={"permissions": ["contracts.read", "contracts.review", "contracts.classify"]},
        headers=HEADERS,
    )
    user = client.post(
        "/v1/users",
        json={"provider": "entra", "issuer": "https://iss", "subject": "alice", "email": "a@x"},
        headers=HEADERS,
    ).json()
    membership = client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={"user_id": user["id"], "application_id": app["id"], "roles": ["lawyer"]},
        headers=HEADERS,
    ).json()
    agents = []
    for name in ["analyzer-1", "analyzer-2"]:
        agent = client.post(
            f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents",
            json={"name": name},
            headers=HEADERS,
        ).json()
        client.put(f"/v1/agents/{agent['id']}/roles", json={"roles": ["analyzer"]}, headers=HEADERS)
        agents.append(agent)
    return {
        "tenant": tenant["id"],
        "app": app["id"],
        "user": user["id"],
        "agent": agents[0]["id"],
        "other_agent": agents[1]["id"],
        "membership": membership["id"],
    }


def _grant(client: TestClient, ids: dict, **body) -> dict:
    payload = {
        "tenant_id": ids["tenant"],
        "application_id": ids["app"],
        "user_id": ids["user"],
        "agent_id": ids["agent"],
        **body,
    }
    r = client.post("/v1/delegations", json=payload, headers=HEADERS)
    assert r.status_code == 201, r.text
    return r.json()


def _authorize(client, ids, token=None, action="read", subject=None, **subject_overrides):
    headers = dict(HEADERS)
    if token:
        headers["X-Delegation-Token"] = token
    subject = subject or {"type": "agent", "user_id": ids["user"], "agent_id": ids["agent"]}
    subject = {**subject, **subject_overrides}
    r = client.post(
        "/v1/authorize",
        json={
            "tenant_id": ids["tenant"],
            "application_id": ids["app"],
            "subject": subject,
            "resource": "contracts",
            "action": action,
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- issuance


def test_default_grant_covers_user_intersect_agent(client):
    ids = _seed(client)
    grant = _grant(client, ids, purpose="review NDA #42")
    assert grant["permissions"] == ["contracts.read", "contracts.review"]
    assert grant["active"] is True and grant["purpose"] == "review NDA #42"
    assert grant["issued_by"].startswith("apikey:")
    assert _authorize(client, ids, grant["token"], "review")["allowed"] is True


def test_grant_cannot_exceed_user_intersect_agent(client):
    ids = _seed(client)
    for perm in ["contracts.approve", "contracts.classify"]:  # user-only / agent-only
        r = client.post(
            "/v1/delegations",
            json={
                "tenant_id": ids["tenant"], "application_id": ids["app"],
                "user_id": ids["user"], "agent_id": ids["agent"], "permissions": [perm],
            },
            headers=HEADERS,
        )
        assert r.status_code == 403
        assert r.json()["detail"] == {"error": "permissions_not_delegable", "permissions": [perm]}


def test_issue_validations(client):
    ids = _seed(client)
    base = {"tenant_id": "acme", "application_id": "contracts", "user_id": ids["user"]}
    r = client.post("/v1/delegations", json={**base, "agent_id": "nope"}, headers=HEADERS)
    assert r.status_code == 404
    r = client.post(
        "/v1/delegations",
        json={**base, "agent_id": ids["agent"], "ttl_seconds": 10**7},
        headers=HEADERS,
    )
    assert r.status_code == 400 and r.json()["detail"]["error"] == "ttl_too_long"
    # Suspended membership → nothing left to delegate.
    client.patch(f"/v1/memberships/{ids['membership']}", json={"status": "suspended"}, headers=HEADERS)
    r = client.post("/v1/delegations", json={**base, "agent_id": ids["agent"]}, headers=HEADERS)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "nothing_to_delegate"


# ---------------------------------------------------------------- narrowing


def test_subset_grant_narrows_all_three_decision_endpoints(client):
    ids = _seed(client)
    token = _grant(client, ids, permissions=["contracts.read"])["token"]

    assert _authorize(client, ids, token, "read")["allowed"] is True
    denied = _authorize(client, ids, token, "review")
    assert denied["allowed"] is False and denied["reason"] == "not_delegated"
    # Without the header the agent keeps its full user ∩ agent set (unchanged behaviour).
    assert _authorize(client, ids, None, "review")["allowed"] is True

    body = {
        "tenant_id": ids["tenant"], "application_id": ids["app"],
        "subject": {"type": "agent", "user_id": ids["user"], "agent_id": ids["agent"]},
    }
    headers = {**HEADERS, "X-Delegation-Token": token}
    eff = client.post("/v1/effective-permissions", json=body, headers=headers).json()
    assert eff["permissions"] == ["contracts.read"]

    bulk = client.post(
        "/v1/bulk-authorize",
        json={**body, "checks": [
            {"resource": "contracts", "action": "read"},
            {"resource": "contracts", "action": "review"},
            {"resource": "contracts", "action": "approve"},
        ]},
        headers=headers,
    ).json()["results"]
    assert [(r["allowed"], r["reason"]) for r in bulk] == [
        (True, "permission_granted"),
        (False, "not_delegated"),
        (False, "missing_permission"),
    ]


def test_live_role_removal_beats_unexpired_grant(client):
    ids = _seed(client)
    token = _grant(client, ids)["token"]
    client.patch(f"/v1/memberships/{ids['membership']}", json={"roles": []}, headers=HEADERS)
    denied = _authorize(client, ids, token, "read")
    assert denied["allowed"] is False and denied["reason"] == "missing_permission"


def test_subject_ids_filled_from_grant(client):
    ids = _seed(client)
    token = _grant(client, ids)["token"]
    assert _authorize(client, ids, token, "read", subject={"type": "agent"})["allowed"] is True


def test_audit_records_delegation_id(client):
    ids = _seed(client)
    grant = _grant(client, ids, permissions=["contracts.read"])
    _authorize(client, ids, grant["token"], "review")
    rows = client.get("/v1/audit", params={"decision": "deny"}, headers=HEADERS).json()
    assert rows[0]["reason"] == "not_delegated"
    assert rows[0]["request"]["delegation_id"] == grant["id"]


# ---------------------------------------------------------------- rejection


def test_token_bound_to_its_agent_user_and_subject_type(client):
    ids = _seed(client)
    token = _grant(client, ids)["token"]
    other = _authorize(client, ids, token, "read", agent_id=ids["other_agent"])
    assert other["reason"] == "delegation_mismatch"
    as_user = _authorize(client, ids, token, "read", subject={"type": "user", "user_id": ids["user"]})
    assert as_user["reason"] == "delegation_mismatch"


def test_tampered_and_garbage_tokens(client):
    ids = _seed(client)
    token = _grant(client, ids, permissions=["contracts.read"])["token"]
    head, payload, sig = token.split(".")
    forged = ".".join([head, payload, sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")])
    assert _authorize(client, ids, forged, "read")["reason"] == "delegation_invalid"
    assert _authorize(client, ids, "not-a-jwt", "read")["reason"] == "delegation_invalid"


def test_revoke_single_and_kill_switch(client):
    ids = _seed(client)
    g1 = _grant(client, ids)
    g2 = _grant(client, ids)
    g3 = _grant(client, ids, agent_id=ids["other_agent"])

    assert client.delete(f"/v1/delegations/{g1['id']}", headers=HEADERS).status_code == 204
    assert _authorize(client, ids, g1["token"], "read")["reason"] == "delegation_revoked"
    assert _authorize(client, ids, g2["token"], "read")["allowed"] is True

    r = client.post(
        "/v1/delegations/revoke",
        json={"tenant_id": ids["tenant"], "agent_id": ids["agent"]},
        headers=HEADERS,
    )
    assert r.json() == {"revoked": 1}
    assert _authorize(client, ids, g2["token"], "read")["reason"] == "delegation_revoked"
    still = _authorize(client, ids, g3["token"], "read", agent_id=ids["other_agent"])
    assert still["allowed"] is True
    assert client.get(f"/v1/delegations/{g1['id']}", headers=HEADERS).json()["status"] == "revoked"


def test_expired_grant_rejected(client, temp_db_url):
    ids = _seed(client)
    grant = _grant(client, ids)
    # The JWT itself is still valid for an hour; the stored row is the authority.
    from sqlalchemy import create_engine, update

    from authzkit.storage import orm

    with create_engine(temp_db_url).begin() as conn:
        conn.execute(
            update(orm.DelegationGrant)
            .where(orm.DelegationGrant.id == grant["id"])
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=5))
        )
    assert _authorize(client, ids, grant["token"], "read")["reason"] == "delegation_expired"


def test_grant_is_never_an_access_token(temp_db_url):
    client = _client(
        temp_db_url, oauth_as_enabled=True, oauth_issuer="https://authz.test"
    )
    ids = _seed(client)
    token = _grant(client, ids)["token"]
    r = client.get("/v1/tenants", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    r = client.post(
        "/v1/authorize",
        json={"tenant_id": ids["tenant"], "application_id": ids["app"],
              "subject": {"type": "agent"}, "resource": "contracts", "action": "read"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


def test_tenant_scoped_caller_cannot_touch_other_tenant_grants(client):
    ids = _seed(client)
    grant = _grant(client, ids)
    other = client.post("/v1/tenants", json={"slug": "other", "name": "O"}, headers=HEADERS).json()
    key = client.post(
        "/v1/api-keys",
        json={"name": "t", "scopes": [f"tenant:{other['id']}"], "tenant_id": other["id"]},
        headers=HEADERS,
    ).json()["key"]
    h = {"X-API-Key": key}
    assert client.delete(f"/v1/delegations/{grant['id']}", headers=h).status_code == 403
    assert client.get(f"/v1/delegations/{grant['id']}", headers=h).status_code == 403
    r = client.post("/v1/delegations/introspect", json={"token": grant["token"]}, headers=h)
    assert r.status_code == 403


# ---------------------------------------------------------------- verification


def test_introspect_and_offline_verification(client):
    ids = _seed(client)
    grant = _grant(client, ids, permissions=["contracts.read"], purpose="triage")
    info = client.post(
        "/v1/delegations/introspect", json={"token": grant["token"]}, headers=HEADERS
    ).json()
    assert info["active"] is True and info["permissions"] == ["contracts.read"]
    bad = client.post("/v1/delegations/introspect", json={"token": "x"}, headers=HEADERS).json()
    assert bad == {"active": False, "reason": "delegation_invalid"}

    # A third party (e.g. an MCP server) can verify offline with the JWKS.
    jwks = client.get("/v1/delegations/jwks").json()
    header = jwt.get_unverified_header(grant["token"])
    assert header["typ"] == "authz-delegation+jwt"
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    claims = jwt.decode(
        grant["token"], jwt.PyJWK(key).key, algorithms=["RS256"],
        audience="urn:authz:delegation",
    )
    assert claims["sub"] == ids["user"]
    assert claims["act"] == {"sub": ids["agent"]}
    assert claims["jti"] == grant["id"]
    assert claims["authz"]["permissions"] == ["contracts.read"]
    assert "scope" not in claims and "tenant_id" not in claims


def test_admin_list_filters(client):
    ids = _seed(client)
    g1 = _grant(client, ids)
    _grant(client, ids, agent_id=ids["other_agent"])
    client.delete(f"/v1/delegations/{g1['id']}", headers=HEADERS)
    all_rows = client.get("/v1/delegations", params={"tenant_id": "acme"}, headers=HEADERS).json()
    assert len(all_rows) == 2
    active = client.get(
        "/v1/delegations", params={"tenant_id": "acme", "active_only": True}, headers=HEADERS
    ).json()
    assert [g["agent_id"] for g in active] == [ids["other_agent"]]


# ---------------------------------------------------------------- opt-in enforcement


def test_delegation_required_mode(temp_db_url):
    client = _client(temp_db_url, delegation_required=True)
    ids = _seed(client)
    assert _authorize(client, ids, None, "read")["reason"] == "delegation_required"
    # Plain user decisions are untouched by the flag.
    user = _authorize(client, ids, None, "read", subject={"type": "user", "user_id": ids["user"]})
    assert user["allowed"] is True
    token = _grant(client, ids)["token"]
    assert _authorize(client, ids, token, "read")["allowed"] is True
    r = client.post(
        "/v1/effective-permissions",
        json={"tenant_id": ids["tenant"], "application_id": ids["app"],
              "subject": {"type": "agent", "user_id": ids["user"], "agent_id": ids["agent"]}},
        headers=HEADERS,
    )
    assert r.status_code == 403 and r.json()["detail"] == {"error": "delegation_required"}


# ---------------------------------------------------------------- Python SDK


def test_sdk_delegated_agent_session(client):
    from authz_sdk import AuthzClient, PermissionDeniedError, Subject
    from authz_sdk.agent_session import delegation_claims, start_delegated_agent_session

    ids = _seed(client)
    sdk = AuthzClient("http://testserver", api_key="test-key", http_client=client,
                      cache_ttl_seconds=60)
    grant = sdk.create_delegation(
        tenant_id=ids["tenant"], application_id=ids["app"], user_id=ids["user"],
        agent_id=ids["agent"], permissions={"contracts.read"}, ttl_seconds=600,
        purpose="read-only triage",
    )
    assert grant.token and grant.permissions == {"contracts.read"}
    assert delegation_claims(grant.token)["agent_id"] == ids["agent"]

    # Prime the cache with the *un*-delegated set; the grant must not hit it.
    subject = Subject(type="agent", user_id=ids["user"], agent_id=ids["agent"])
    full = sdk.get_effective_permissions(
        tenant_id=ids["tenant"], application_id=ids["app"], subject=subject
    )
    assert full == {"contracts.read", "contracts.review"}

    guard = start_delegated_agent_session(sdk, grant.token, critical_actions=["contracts.read"])
    assert guard.permissions == {"contracts.read"}
    guard.require("contracts", "read")
    with pytest.raises(PermissionDeniedError):
        guard.require("contracts", "review")

    assert sdk.introspect_delegation(grant.token)["active"] is True
    sdk.revoke_delegation(grant.id)
    assert sdk.get_delegation(grant.id).status == "revoked"
    # Critical action revalidates remotely → the revoked grant now fails.
    with pytest.raises(PermissionDeniedError):
        guard.require("contracts", "read")
    assert sdk.introspect_delegation(grant.token) == {"active": False, "reason": "delegation_revoked"}

    sdk.create_delegation(tenant_id=ids["tenant"], application_id=ids["app"],
                          user_id=ids["user"], agent_id=ids["agent"])
    assert sdk.revoke_delegations(tenant_id=ids["tenant"], user_id=ids["user"]) == 1
