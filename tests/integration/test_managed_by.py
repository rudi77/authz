"""Z-4: an application with ``managed_by`` is writable only by its manager."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import OPERATOR, make_env


def _ids(env) -> dict:
    """A tenant with one member and one agent in the managed app ``dtm``."""
    c = env.client
    app = c.get("/v1/applications/dtm", headers=OPERATOR).json()
    tenant = c.post("/v1/tenants", json={"slug": "acme", "name": "ACME"}, headers=OPERATOR).json()
    user = c.post(
        "/v1/users",
        json={"provider": "dtm", "issuer": "urn:dtm:test", "subject": "ada"},
        headers=OPERATOR,
    ).json()
    membership = c.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={"user_id": user["id"], "application_id": app["id"], "roles": ["Operator"]},
        headers=env.manager,
    )
    assert membership.status_code == 201, membership.text
    agent = c.post(
        f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents",
        json={"name": "bot"},
        headers=env.manager,
    )
    assert agent.status_code == 201, agent.text
    role = next(
        r
        for r in c.get(f"/v1/applications/{app['id']}/roles", headers=OPERATOR).json()
        if r["name"] == "Operator"
    )
    return {
        "app": app["id"],
        "tenant": tenant["id"],
        "user": user["id"],
        "membership": membership.json()["id"],
        "agent": agent.json()["id"],
        "role": role["id"],
    }


def _writes(ids: dict) -> list[tuple[str, str, dict]]:
    return [
        ("POST", f"/v1/applications/{ids['app']}/permissions", {"name": "x.y"}),
        ("POST", f"/v1/applications/{ids['app']}/roles", {"name": "Extra"}),
        ("PUT", f"/v1/roles/{ids['role']}/permissions", {"permissions": ["runs.start"]}),
        (
            "POST",
            f"/v1/tenants/{ids['tenant']}/memberships",
            {"user_id": ids["user"], "application_id": "dtm", "roles": []},
        ),
        ("PATCH", f"/v1/memberships/{ids['membership']}", {"status": "suspended"}),
        (
            "POST",
            f"/v1/tenants/{ids['tenant']}/applications/{ids['app']}/agents",
            {"name": "other"},
        ),
        ("PUT", f"/v1/agents/{ids['agent']}/roles", {"roles": ["Operator"]}),
        (
            "POST",
            f"/v1/tenants/{ids['tenant']}/invitations",
            {"email": "x@acme.test", "application_id": "dtm", "roles": ["Operator"]},
        ),
    ]


def test_platform_operator_cannot_write_managed_application(temp_db_url):
    env = make_env(temp_db_url)
    ids = _ids(env)
    for method, path, body in _writes(ids):
        r = env.client.request(method, path, json=body, headers=OPERATOR)
        assert r.status_code == 403, (method, path, r.text)
        assert r.json()["detail"] == {
            "error": "application_managed_externally",
            "managed_by": env.manager_label,
        }


def test_manager_can_write_managed_application(temp_db_url):
    env = make_env(temp_db_url)
    ids = _ids(env)
    r = env.client.post(
        f"/v1/applications/{ids['app']}/permissions", json={"name": "x.y"}, headers=env.manager
    )
    assert r.status_code == 201
    r = env.client.put(
        f"/v1/agents/{ids['agent']}/roles", json={"roles": ["Operator"]}, headers=env.manager
    )
    assert r.status_code == 200


def test_platform_surfaces_stay_open(temp_db_url):
    env = make_env(temp_db_url)
    ids = _ids(env)
    c = env.client
    r = c.put(
        f"/v1/tenants/{ids['tenant']}/applications/dtm/permission-mask",
        json={"permissions": ["runs.start"]},
        headers=OPERATOR,
    )
    assert r.status_code == 200
    r = c.put(
        f"/v1/tenants/{ids['tenant']}/feature-flags",
        json={"application_id": "dtm", "key": "k", "value": True},
        headers=OPERATOR,
    )
    assert r.status_code == 200
    # Reads stay open too.
    assert c.get(f"/v1/applications/{ids['app']}/roles", headers=OPERATOR).status_code == 200


def test_release_management_unlocks_and_is_audited(temp_db_url):
    env = make_env(temp_db_url)
    ids = _ids(env)
    c = env.client
    r = c.post("/v1/applications/dtm/release-management", headers=env.runtime)
    assert r.status_code == 403

    r = c.post("/v1/applications/dtm/release-management", headers=OPERATOR)
    assert r.status_code == 200, r.text
    assert r.json()["managed_by"] is None
    assert "managed_by" not in c.get("/v1/applications/dtm", headers=OPERATOR).json()

    r = c.post(
        f"/v1/applications/{ids['app']}/permissions", json={"name": "x.y"}, headers=OPERATOR
    )
    assert r.status_code == 201

    audit = c.get("/v1/audit", headers=OPERATOR).json()
    released = [a for a in audit if a["reason"] == "management_released"]
    assert len(released) == 1
    assert released[0]["application_id"] == ids["app"]
    assert released[0]["request"]["managed_by"] == env.manager_label
