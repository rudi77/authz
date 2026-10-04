"""Z-1: decisions and delegations accept references instead of authz ids.

Tenant and application by id or slug, the user by ``user_ref`` (identity at
the IdP), the agent by ``agent_name``. References resolve before the tenant
scope binding and the delegation match; responses carry resolved UUIDs.
"""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import OPERATOR, make_env, member, user_ref

TENANT = "6f1c0000-0000-0000-0000-0000000000aa"
AGENT = "profile:invoice-agent"


@pytest.fixture()
def env(temp_db_url):
    env = make_env(temp_db_url)
    r = env.client.put(
        f"/v1/applications/dtm/tenants/{TENANT}/state",
        json={
            "name": "ACME",
            "members": [member("ada", ["Approver"])],
            "agents": [
                {"name": AGENT, "permissions": ["mcp.sap-prod.read", "tools.file_read.invoke"]}
            ],
        },
        headers=env.manager,
    )
    assert r.status_code == 200, r.text
    tenant = env.client.get(f"/v1/tenants/{TENANT}", headers=OPERATOR).json()
    app = env.client.get("/v1/applications/dtm", headers=OPERATOR).json()
    membership = env.client.get(f"/v1/tenants/{tenant['id']}/memberships", headers=OPERATOR).json()
    agent = env.client.get(
        f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents", headers=OPERATOR
    ).json()
    env.ids = {  # type: ignore[attr-defined]
        "tenant": tenant["id"],
        "app": app["id"],
        "user": membership[0]["user_id"],
        "agent": agent[0]["id"],
    }
    return env


def _agent_subject(**overrides) -> dict:
    return {"type": "agent", "user_ref": user_ref("ada"), "agent_name": AGENT, **overrides}


def _authorize(env, subject, *, tenant=TENANT, app="dtm", action="read", headers=None):
    r = env.client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant,
            "application_id": app,
            "subject": subject,
            "resource": "mcp.sap-prod",
            "action": action,
        },
        headers=headers or env.runtime,
    )
    return r


def test_authorize_with_references(env):
    r = _authorize(env, {"type": "user", "user_ref": user_ref("ada")})
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True
    r = _authorize(env, _agent_subject())
    assert r.json()["allowed"] is True
    r = _authorize(env, _agent_subject(), action="write")
    assert r.json()["reason"] == "missing_permission"
    # ids keep working, mixed forms too.
    r = _authorize(
        env,
        {"type": "agent", "user_id": env.ids["user"], "agent_name": AGENT},
        tenant=env.ids["tenant"],
        app=env.ids["app"],
    )
    assert r.json()["allowed"] is True


def test_both_forms_of_one_field_is_422(env):
    r = _authorize(
        env, {"type": "user", "user_id": env.ids["user"], "user_ref": user_ref("ada")}
    )
    assert r.status_code == 422
    r = _authorize(env, _agent_subject(agent_id=env.ids["agent"]))
    assert r.status_code == 422


@pytest.mark.parametrize(
    ("kwargs", "subject", "reason"),
    [
        ({"tenant": "unknown-tenant"}, None, "tenant_not_active"),
        ({"app": "unknown-app"}, None, "application_not_active"),
        ({}, {"type": "user", "user_ref": user_ref("nobody")}, "no_active_membership"),
        ({}, {"type": "agent", "user_ref": user_ref("nobody"), "agent_name": AGENT}, "no_active_user_membership"),
        ({}, {"type": "agent", "user_ref": user_ref("ada"), "agent_name": "profile:ghost"}, "agent_not_active"),
    ],
)
def test_unknown_references_deny(env, kwargs, subject, reason):
    r = _authorize(env, subject or {"type": "user", "user_ref": user_ref("ada")}, **kwargs)
    assert r.status_code == 200
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == reason


def test_bulk_and_effective_permissions_with_references(env):
    body = {"tenant_id": TENANT, "application_id": "dtm", "subject": _agent_subject()}
    r = env.client.post(
        "/v1/bulk-authorize",
        json={
            **body,
            "checks": [
                {"resource": "mcp.sap-prod", "action": "read"},
                {"resource": "mcp.sap-prod", "action": "write"},
            ],
        },
        headers=env.runtime,
    )
    assert [c["allowed"] for c in r.json()["results"]] == [True, False]

    r = env.client.post("/v1/effective-permissions", json=body, headers=env.runtime)
    assert r.status_code == 200, r.text
    eff = r.json()
    assert eff["tenant_id"] == env.ids["tenant"]
    assert eff["application_id"] == env.ids["app"]
    assert eff["subject"]["user_id"] == env.ids["user"]
    assert eff["subject"]["agent_id"] == env.ids["agent"]
    assert eff["permissions"] == ["mcp.sap-prod.read", "tools.file_read.invoke"]

    unknown = {**body, "tenant_id": "unknown"}
    r = env.client.post("/v1/effective-permissions", json=unknown, headers=env.runtime)
    assert r.status_code == 200
    assert r.json()["permissions"] == []


def test_delegation_issue_use_and_revoke_with_references(env):
    grant_body = {
        "tenant_id": TENANT,
        "application_id": "dtm",
        "user_ref": user_ref("ada"),
        "agent_name": AGENT,
        "permissions": ["mcp.sap-prod.read"],
    }
    r = env.client.post("/v1/delegations", json=grant_body, headers=env.runtime)
    assert r.status_code == 201, r.text
    grant = r.json()
    assert grant["tenant_id"] == env.ids["tenant"]
    assert grant["user_id"] == env.ids["user"]
    assert grant["agent_id"] == env.ids["agent"]

    headers = {**env.runtime, "X-Delegation-Token": grant["token"]}
    assert _authorize(env, _agent_subject(), headers=headers).json()["allowed"] is True
    denied = _authorize(env, _agent_subject(), headers=headers, action="write")
    assert denied.json()["reason"] in {"not_delegated", "missing_permission"}

    listed = env.client.get(
        "/v1/delegations",
        params={
            "tenant_id": TENANT,
            "user_provider": "dtm",
            "user_issuer": "urn:dtm:test",
            "user_subject": "ada",
            "application_id": "dtm",
            "agent_name": AGENT,
        },
        headers=OPERATOR,
    ).json()
    assert [g["id"] for g in listed] == [grant["id"]]
    nobody = env.client.get(
        "/v1/delegations",
        params={
            "tenant_id": TENANT,
            "user_provider": "dtm",
            "user_issuer": "urn:dtm:test",
            "user_subject": "nobody",
        },
        headers=OPERATOR,
    ).json()
    assert nobody == []

    r = env.client.post(
        "/v1/delegations/revoke",
        json={"tenant_id": TENANT, "application_id": "dtm", "agent_name": AGENT},
        headers=env.runtime,
    )
    assert r.json() == {"revoked": 1}
    revoked = _authorize(env, _agent_subject(), headers=headers)
    assert revoked.json()["reason"] == "delegation_revoked"


def test_delegation_unknown_references_are_404(env):
    base = {"tenant_id": TENANT, "application_id": "dtm"}
    cases = [
        ({**base, "tenant_id": "nope", "user_ref": user_ref("ada"), "agent_name": AGENT}, "tenant_not_found"),
        ({**base, "application_id": "nope", "user_ref": user_ref("ada"), "agent_name": AGENT}, "application_not_found"),
        ({**base, "user_ref": user_ref("nobody"), "agent_name": AGENT}, "user_not_found"),
        ({**base, "user_ref": user_ref("ada"), "agent_name": "profile:ghost"}, "agent_not_found"),
    ]
    for body, reason in cases:
        r = env.client.post("/v1/delegations", json=body, headers=env.runtime)
        assert r.status_code == 404, (body, r.text)
        assert r.json()["detail"]["reason"] == reason
    r = env.client.post(
        "/v1/delegations/revoke",
        json={**base, "user_ref": user_ref("nobody")},
        headers=env.runtime,
    )
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "user_not_found"


def test_delegation_reference_validation_is_422(env):
    base = {"tenant_id": TENANT, "application_id": "dtm"}
    for body in (
        {**base, "user_ref": user_ref("ada"), "user_id": env.ids["user"], "agent_name": AGENT},
        {**base, "user_ref": user_ref("ada"), "agent_name": AGENT, "agent_id": env.ids["agent"]},
        {**base, "agent_name": AGENT},
        {**base, "user_ref": user_ref("ada")},
    ):
        r = env.client.post("/v1/delegations", json=body, headers=env.runtime)
        assert r.status_code == 422, body
    r = env.client.post(
        "/v1/delegations/revoke", json={"tenant_id": TENANT, "agent_name": AGENT}, headers=env.runtime
    )
    assert r.status_code == 422


def test_tenant_bound_caller_may_use_the_tenant_slug(env):
    key = env.client.post(
        "/v1/api-keys",
        json={"name": "acme-pep", "scopes": ["runtime"], "tenant_id": env.ids["tenant"]},
        headers=OPERATOR,
    ).json()["key"]
    r = _authorize(env, {"type": "user", "user_ref": user_ref("ada")}, headers={"X-API-Key": key})
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True
