"""Z-2: declarative tenant state (``PUT /v1/applications/{app}/tenants/{tenant}/state``)."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import OPERATOR, make_env, member

STATE = {
    "name": "ACME",
    "status": "active",
    "members": [member("ada", ["Operator", "Approver"]), member("bob", ["Operator"])],
    "agents": [
        {
            "name": "profile:invoice-agent",
            "display_name": "Invoice Agent",
            "permissions": ["tools.file_read.invoke", "mcp.sap-prod.read"],
        }
    ],
}
TENANT = "6f1c0000-0000-0000-0000-000000000001"


def _put(env, state=STATE, headers=None, tenant=TENANT):
    return env.client.put(
        f"/v1/applications/dtm/tenants/{tenant}/state",
        json=state,
        headers=headers or env.manager,
    )


def _snapshot(env) -> dict:
    c = env.client
    app = c.get("/v1/applications/dtm", headers=OPERATOR).json()
    tenant = c.get(f"/v1/tenants/{TENANT}", headers=OPERATOR).json()
    users = {u["id"]: u for u in c.get("/v1/users", headers=OPERATOR).json()}
    memberships = {
        users[m["user_id"]]["identities"][0]["subject"]: m
        for m in c.get(f"/v1/tenants/{tenant['id']}/memberships", headers=OPERATOR).json()
    }
    agents = {
        a["name"]: a
        for a in c.get(
            f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents", headers=OPERATOR
        ).json()
    }
    return {"app": app, "tenant": tenant, "users": users, "memberships": memberships, "agents": agents}


def _effective(env, snap, subject: dict) -> list[str]:
    r = env.client.post(
        "/v1/effective-permissions",
        json={
            "tenant_id": snap["tenant"]["id"],
            "application_id": snap["app"]["id"],
            "subject": subject,
        },
        headers=env.runtime,
    )
    assert r.status_code == 200, r.text
    return r.json()["permissions"]


def test_state_creates_tenant_users_memberships_and_agents(temp_db_url):
    env = make_env(temp_db_url)
    r = _put(env)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["members"] == {"created": 2, "updated": 0, "disabled": 0}
    assert body["agents"] == {"created": 1, "updated": 0, "disabled": 0}

    snap = _snapshot(env)
    assert body["tenant_id"] == snap["tenant"]["id"]
    assert snap["tenant"]["name"] == "ACME"
    ada = snap["memberships"]["ada"]
    assert ada["roles"] == ["Approver", "Operator"]
    assert ada["status"] == "active"
    assert snap["users"][ada["user_id"]]["email"] == "ada@acme.test"

    agent = snap["agents"]["profile:invoice-agent"]
    assert agent["display_name"] == "Invoice Agent"
    roles = env.client.get(f"/v1/agents/{agent['id']}/roles", headers=OPERATOR).json()
    assert roles["roles"] == ["agent:profile:invoice-agent"]

    assert _effective(env, snap, {"type": "user", "user_id": ada["user_id"]}) == [
        "mcp.sap-prod.read",
        "runs.start",
        "tools.file_read.invoke",
    ]
    assert _effective(
        env, snap, {"type": "agent", "user_id": ada["user_id"], "agent_id": agent["id"]}
    ) == ["mcp.sap-prod.read", "tools.file_read.invoke"]


def test_state_is_idempotent(temp_db_url):
    env = make_env(temp_db_url)
    _put(env)
    r = _put(env)
    assert r.json()["members"] == {"created": 0, "updated": 0, "disabled": 0}
    assert r.json()["agents"] == {"created": 0, "updated": 0, "disabled": 0}


def test_absent_members_and_agents_are_disabled(temp_db_url):
    env = make_env(temp_db_url)
    _put(env)
    smaller = {
        **STATE,
        "members": [member("ada", ["Operator"])],
        "agents": [],
    }
    r = _put(env, smaller)
    assert r.status_code == 200, r.text
    assert r.json()["members"] == {"created": 0, "updated": 1, "disabled": 1}
    assert r.json()["agents"] == {"created": 0, "updated": 0, "disabled": 1}
    snap = _snapshot(env)
    assert snap["memberships"]["bob"]["status"] == "disabled"
    assert snap["memberships"]["ada"]["roles"] == ["Operator"]
    assert snap["agents"]["profile:invoice-agent"]["status"] == "disabled"

    # Re-listing re-enables.
    r = _put(env)
    assert r.json()["members"] == {"created": 0, "updated": 2, "disabled": 0}
    assert r.json()["agents"] == {"created": 0, "updated": 1, "disabled": 0}


def test_member_and_agent_status_from_state(temp_db_url):
    env = make_env(temp_db_url)
    state = {
        **STATE,
        "members": [member("ada", ["Operator"], status="disabled")],
        "agents": [{"name": "bot", "permissions": [], "status": "disabled"}],
    }
    assert _put(env, state).status_code == 200
    snap = _snapshot(env)
    assert snap["memberships"]["ada"]["status"] == "disabled"
    assert snap["agents"]["bot"]["status"] == "disabled"


def test_invalid_state_reports_all_errors_and_applies_nothing(temp_db_url):
    env = make_env(temp_db_url)
    bad = {
        "name": "ACME",
        "members": [
            member("ada", ["Operator", "Ghost"]),
            member("ada", ["Operator"]),
            member("eve", [], status="weird"),
        ],
        "agents": [
            {"name": "bot", "permissions": ["runs.start", "mcp.nope.write"]},
            {"name": "bot", "permissions": []},
        ],
    }
    r = _put(env, bad)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_state"
    assert [(e["path"], e["code"]) for e in detail["errors"]] == [
        ("members[0].roles[1]", "unknown_role"),
        ("members[1].user_ref", "duplicate_member"),
        ("members[2].status", "invalid_status"),
        ("agents[0].permissions[1]", "unknown_permission"),
        ("agents[1].name", "duplicate_agent"),
    ]
    assert all(e["message"] for e in detail["errors"])
    assert env.client.get(f"/v1/tenants/{TENANT}", headers=OPERATOR).status_code == 404
    assert env.client.get("/v1/users", headers=OPERATOR).json() == []


def test_internal_agent_roles_are_not_assignable_by_name(temp_db_url):
    env = make_env(temp_db_url)
    _put(env)
    bad = {**STATE, "members": [member("ada", ["agent:profile:invoice-agent"])]}
    r = _put(env, bad)
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["code"] == "unknown_role"


def test_only_the_manager_may_write_state(temp_db_url):
    env = make_env(temp_db_url)
    r = _put(env, headers=OPERATOR)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "application_managed_externally"
    r = _put(env, headers=env.runtime)
    assert r.status_code == 403


def test_state_on_unmanaged_application_is_rejected(temp_db_url):
    env = make_env(temp_db_url, with_catalog=False)
    env.client.post("/v1/applications", json={"slug": "dtm", "name": "DTM"}, headers=OPERATOR)
    r = _put(env, {"name": "ACME"}, headers=OPERATOR)
    assert r.status_code == 403
    assert r.json()["detail"] == {"error": "application_not_managed"}


def test_state_for_unknown_application_is_404(temp_db_url):
    env = make_env(temp_db_url)
    r = env.client.put(
        f"/v1/applications/nope/tenants/{TENANT}/state", json={"name": "X"}, headers=env.manager
    )
    assert r.status_code == 404
