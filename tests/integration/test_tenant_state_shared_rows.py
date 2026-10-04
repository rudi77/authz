"""Z-2: tenants and users are shared by all applications.

The tenant-state PUT of one managed application may create a missing tenant
or user, but never changes an existing tenant's name/status or an existing
user's profile — otherwise one application's manager could suspend or rename
a tenant (or a person) for every other application.
"""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import OPERATOR, make_env, member

TENANT = "6f1c0000-0000-0000-0000-0000000000bb"


def _put(env, state):
    return env.client.put(
        f"/v1/applications/dtm/tenants/{TENANT}/state", json=state, headers=env.manager
    )


def _user(env, subject: str) -> dict:
    users = env.client.get("/v1/users", headers=OPERATOR).json()
    return next(u for u in users if u["identities"][0]["subject"] == subject)


def test_new_tenant_and_user_are_created_with_the_given_values(temp_db_url):
    env = make_env(temp_db_url)
    r = _put(env, {"name": "ACME", "members": [member("ada", ["Operator"])]})
    assert r.status_code == 200, r.text
    tenant = env.client.get(f"/v1/tenants/{TENANT}", headers=OPERATOR).json()
    assert (tenant["name"], tenant["status"]) == ("ACME", "active")
    ada = _user(env, "ada")
    assert (ada["display_name"], ada["email"]) == ("Ada", "ada@acme.test")


def test_existing_tenant_keeps_name_and_status(temp_db_url):
    env = make_env(temp_db_url)
    c = env.client
    created = c.post("/v1/tenants", json={"slug": TENANT, "name": "Platform name"}, headers=OPERATOR)
    assert created.status_code == 201, created.text
    tenant_id = created.json()["id"]
    assert c.patch(
        f"/v1/tenants/{tenant_id}", json={"status": "suspended"}, headers=OPERATOR
    ).status_code == 200

    r = _put(env, {"name": "ACME", "status": "active", "members": [member("ada", ["Operator"])]})
    assert r.status_code == 200, r.text
    assert r.json()["tenant_id"] == tenant_id
    tenant = c.get(f"/v1/tenants/{tenant_id}", headers=OPERATOR).json()
    assert (tenant["name"], tenant["status"]) == ("Platform name", "suspended")


def test_existing_user_profile_is_not_overwritten(temp_db_url):
    env = make_env(temp_db_url)
    c = env.client
    r = c.post(
        "/v1/users",
        json={
            "provider": "dtm",
            "issuer": "urn:dtm:test",
            "subject": "ada",
            "display_name": "Ada Lovelace",
            "email": "ada@platform.test",
        },
        headers=OPERATOR,
    )
    assert r.status_code in (200, 201), r.text

    assert _put(env, {"name": "ACME", "members": [member("ada", ["Operator"])]}).status_code == 200
    ada = _user(env, "ada")
    assert (ada["display_name"], ada["email"]) == ("Ada Lovelace", "ada@platform.test")


def test_tenant_status_other_than_active_is_rejected(temp_db_url):
    env = make_env(temp_db_url)
    r = _put(env, {"name": "ACME", "status": "suspended"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_state"
    assert [(e["path"], e["code"]) for e in detail["errors"]] == [
        ("status", "tenant_status_not_managed")
    ]
    assert env.client.get(f"/v1/tenants/{TENANT}", headers=OPERATOR).status_code == 404
