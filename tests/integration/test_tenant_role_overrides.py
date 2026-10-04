"""Z-8: tenant overrides of default roles (``…/tenants/{tenant}/roles``)."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import OPERATOR, make_env, member

ROLES = "/v1/applications/dtm/tenants/{tenant}/roles"


def _setup(env, tenant: str = "acme") -> dict:
    r = env.client.put(
        f"/v1/applications/dtm/tenants/{tenant}/state",
        json={"name": tenant, "members": [member(f"ada-{tenant}", ["Operator"])]},
        headers=env.manager,
    )
    assert r.status_code == 200, r.text
    tenant_id = r.json()["tenant_id"]
    membership = env.client.get(f"/v1/tenants/{tenant_id}/memberships", headers=OPERATOR).json()[0]
    app_id = env.client.get("/v1/applications/dtm", headers=OPERATOR).json()["id"]
    return {"tenant": tenant_id, "user": membership["user_id"], "app": app_id}


def _effective(env, ids) -> list[str]:
    r = env.client.post(
        "/v1/effective-permissions",
        json={
            "tenant_id": ids["tenant"],
            "application_id": ids["app"],
            "subject": {"type": "user", "user_id": ids["user"]},
        },
        headers=env.runtime,
    )
    return r.json()["permissions"]


def test_list_shows_defaults(temp_db_url):
    env = make_env(temp_db_url)
    _setup(env)
    r = env.client.get(ROLES.format(tenant="acme"), headers=env.runtime)
    assert r.status_code == 200, r.text
    assert r.json() == [
        {
            "name": "Approver",
            "source": "application",
            "permissions": ["mcp.sap-prod.read", "runs.start", "tools.file_read.invoke"],
            "default_permissions": ["mcp.sap-prod.read", "runs.start", "tools.file_read.invoke"],
        },
        {
            "name": "Operator",
            "source": "application",
            "permissions": ["runs.start"],
            "default_permissions": ["runs.start"],
        },
    ]


def test_override_applies_to_this_tenant_only_and_reset_restores_default(temp_db_url):
    env = make_env(temp_db_url)
    acme = _setup(env, "acme")
    other = _setup(env, "globex")
    assert _effective(env, acme) == ["runs.start"]

    r = env.client.put(
        ROLES.format(tenant="acme") + "/Operator",
        json={"permissions": ["runs.start", "mcp.sap-prod.read"]},
        headers=env.manager,
    )
    assert r.status_code == 200, r.text
    assert r.json() == {
        "name": "Operator",
        "source": "tenant",
        "permissions": ["mcp.sap-prod.read", "runs.start"],
        "default_permissions": ["runs.start"],
    }
    assert _effective(env, acme) == ["mcp.sap-prod.read", "runs.start"]
    assert _effective(env, other) == ["runs.start"]

    # A member provisioned while the override exists still falls back to the
    # default once the override is gone.
    env.client.put(
        "/v1/applications/dtm/tenants/acme/state",
        json={"name": "acme", "members": [member("ada-acme", ["Operator"]), member("cy", ["Operator"])]},
        headers=env.manager,
    )
    r = env.client.delete(ROLES.format(tenant="acme") + "/Operator", headers=env.manager)
    assert r.status_code == 204
    assert _effective(env, acme) == ["runs.start"]
    members = env.client.get(f"/v1/tenants/{acme['tenant']}/memberships", headers=OPERATOR).json()
    assert [m["roles"] for m in members] == [["Operator"], ["Operator"]]
    listed = env.client.get(ROLES.format(tenant="acme"), headers=env.runtime).json()
    assert {r["name"]: r["source"] for r in listed} == {
        "Approver": "application",
        "Operator": "application",
    }

    # Idempotent.
    r = env.client.delete(ROLES.format(tenant="acme") + "/Operator", headers=env.manager)
    assert r.status_code == 204


def test_override_validation(temp_db_url):
    env = make_env(temp_db_url)
    _setup(env)
    r = env.client.put(
        ROLES.format(tenant="acme") + "/Ghost", json={"permissions": []}, headers=env.manager
    )
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "role_not_found"
    r = env.client.put(
        ROLES.format(tenant="acme") + "/Operator",
        json={"permissions": ["runs.start", "runs.nuke"]},
        headers=env.manager,
    )
    assert r.status_code == 422
    assert r.json()["detail"] == {"error": "unknown_permission", "permissions": ["runs.nuke"]}
    r = env.client.delete(ROLES.format(tenant="acme") + "/Ghost", headers=env.manager)
    assert r.status_code == 404
    r = env.client.get(ROLES.format(tenant="nope"), headers=env.runtime)
    assert r.status_code == 404


def test_only_the_manager_may_change_overrides(temp_db_url):
    env = make_env(temp_db_url)
    _setup(env)
    for headers in (OPERATOR, env.runtime):
        r = env.client.put(
            ROLES.format(tenant="acme") + "/Operator",
            json={"permissions": []},
            headers=headers,
        )
        assert r.status_code == 403
        r = env.client.delete(ROLES.format(tenant="acme") + "/Operator", headers=headers)
        assert r.status_code == 403
