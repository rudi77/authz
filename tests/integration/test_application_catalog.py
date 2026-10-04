"""Z-3: declarative application catalog (``PUT /v1/applications/{slug}/catalog``)."""

from __future__ import annotations

import copy

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import CATALOG, OPERATOR, make_env, member


def _permissions(env) -> dict[str, dict]:
    rows = env.client.get("/v1/applications/dtm/permissions", headers=OPERATOR).json()
    return {p["name"]: p for p in rows}


def _roles(env) -> dict[str, dict]:
    rows = env.client.get("/v1/applications/dtm/roles", headers=OPERATOR).json()
    return {r["name"]: r for r in rows}


def test_catalog_creates_application_permissions_and_roles(temp_db_url):
    env = make_env(temp_db_url, with_catalog=False)
    r = env.client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=env.manager)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["permissions"] == {"created": 4, "deprecated": 0}
    assert body["roles"] == {"created": 2, "updated": 0}

    app = env.client.get("/v1/applications/dtm", headers=OPERATOR).json()
    assert app["id"] == body["application_id"]
    assert app["name"] == "Digital Teammates"
    assert app["managed_by"] == env.manager_label

    perms = _permissions(env)
    assert perms["mcp.sap-prod.write"]["critical"] is True
    assert perms["runs.start"]["description"] == "Start runs"
    assert not any(p.get("deprecated") for p in perms.values())

    roles = _roles(env)
    assert roles["Operator"]["tenant_id"] is None
    approver = env.client.get(
        f"/v1/roles/{roles['Approver']['id']}/permissions", headers=OPERATOR
    ).json()
    assert approver["permissions"] == [
        "mcp.sap-prod.read",
        "runs.start",
        "tools.file_read.invoke",
    ]


def test_catalog_is_idempotent_and_replaces_role_permissions(temp_db_url):
    env = make_env(temp_db_url)
    r = env.client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=env.manager)
    assert r.json()["permissions"] == {"created": 0, "deprecated": 0}
    assert r.json()["roles"] == {"created": 0, "updated": 2}

    changed = copy.deepcopy(CATALOG)
    changed["default_roles"][1]["permissions"] = ["runs.start"]
    env.client.put("/v1/applications/dtm/catalog", json=changed, headers=env.manager)
    approver = _roles(env)["Approver"]
    perms = env.client.get(f"/v1/roles/{approver['id']}/permissions", headers=OPERATOR).json()
    assert perms["permissions"] == ["runs.start"]


def test_missing_permissions_are_deprecated_and_stop_counting(temp_db_url):
    env = make_env(temp_db_url)
    env.client.put(
        "/v1/applications/dtm/tenants/acme/state",
        json={"name": "ACME", "members": [member("ada", ["Approver"])], "agents": []},
        headers=env.manager,
    )
    tenant = env.client.get("/v1/tenants/acme", headers=OPERATOR).json()
    membership = env.client.get(
        f"/v1/tenants/{tenant['id']}/memberships", headers=OPERATOR
    ).json()[0]
    app_id = env.client.get("/v1/applications/dtm", headers=OPERATOR).json()["id"]

    def can_read_sap() -> bool:
        r = env.client.post(
            "/v1/authorize",
            json={
                "tenant_id": tenant["id"],
                "application_id": app_id,
                "subject": {"type": "user", "user_id": membership["user_id"]},
                "resource": "mcp.sap-prod",
                "action": "read",
            },
            headers=env.runtime,
        )
        return r.json()["allowed"]

    assert can_read_sap()

    shrunk = copy.deepcopy(CATALOG)
    shrunk["permissions"] = [p for p in shrunk["permissions"] if p["name"] != "mcp.sap-prod.read"]
    shrunk["default_roles"] = []  # Approver keeps its (now deprecated) link
    r = env.client.put("/v1/applications/dtm/catalog", json=shrunk, headers=env.manager)
    assert r.status_code == 200, r.text
    assert r.json()["permissions"] == {"created": 0, "deprecated": 1}
    assert _permissions(env)["mcp.sap-prod.read"]["deprecated"] is True
    assert not can_read_sap()

    # A deprecated permission is unknown for assignments.
    approver = _roles(env)["Approver"]
    r = env.client.put(
        f"/v1/roles/{approver['id']}/permissions",
        json={"permissions": ["mcp.sap-prod.read"]},
        headers=env.manager,
    )
    assert r.status_code == 422

    # Listing it again reactivates it.
    env.client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=env.manager)
    assert "deprecated" not in _permissions(env)["mcp.sap-prod.read"]
    assert can_read_sap()


def test_unknown_permission_in_default_role_is_422_and_nothing_applied(temp_db_url):
    env = make_env(temp_db_url, with_catalog=False)
    bad = copy.deepcopy(CATALOG)
    bad["default_roles"][0]["permissions"] = ["runs.start", "runs.nuke"]
    r = env.client.put("/v1/applications/dtm/catalog", json=bad, headers=env.manager)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_catalog"
    assert detail["errors"] == [
        {
            "path": "default_roles[0].permissions[1]",
            "code": "unknown_permission",
            "message": "permission 'runs.nuke' is not in the catalog",
        }
    ]
    assert env.client.get("/v1/applications/dtm", headers=OPERATOR).status_code == 404


def test_invalid_permission_name_is_422(temp_db_url):
    env = make_env(temp_db_url, with_catalog=False)
    r = env.client.put(
        "/v1/applications/dtm/catalog",
        json={"name": "X", "permissions": [{"name": "nodot"}], "default_roles": []},
        headers=env.manager,
    )
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["code"] == "invalid_permission_name"


def test_catalog_requires_admin_scope(temp_db_url):
    env = make_env(temp_db_url, with_catalog=False)
    r = env.client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=env.runtime)
    assert r.status_code == 403


def test_catalog_of_managed_application_rejects_other_callers(temp_db_url):
    env = make_env(temp_db_url)
    r = env.client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=OPERATOR)
    assert r.status_code == 403
    assert r.json()["detail"] == {
        "error": "application_managed_externally",
        "managed_by": env.manager_label,
    }


def test_catalog_on_existing_unmanaged_application_does_not_claim_it(temp_db_url):
    env = make_env(temp_db_url, with_catalog=False)
    env.client.post("/v1/applications", json={"slug": "dtm", "name": "Old"}, headers=OPERATOR)
    r = env.client.put("/v1/applications/dtm/catalog", json=CATALOG, headers=env.manager)
    assert r.status_code == 200
    app = env.client.get("/v1/applications/dtm", headers=OPERATOR).json()
    assert "managed_by" not in app  # null is omitted (older SDKs stay compatible)
    assert app["name"] == "Digital Teammates"
