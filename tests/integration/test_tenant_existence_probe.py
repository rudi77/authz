"""A tenant-bound caller learns nothing about other tenants.

Routes that resolve references (``POST /v1/delegations``, ``POST
/v1/delegations/revoke``, ``GET …/tenants/{tenant}/roles``) apply the tenant
scope binding on the resolved tenant before they resolve users or agents.
A caller bound to tenant A asking about tenant B gets 403 — whether or not
tenant B, its users or its agents exist.
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
            "agents": [{"name": AGENT, "permissions": ["mcp.sap-prod.read"]}],
        },
        headers=env.manager,
    )
    assert r.status_code == 200, r.text
    return env


@pytest.fixture(params=["pinned_runtime_key", "tenant_scope_key"])
def other_tenant_caller(env, request) -> dict[str, str]:
    """A caller bound to another tenant than ACME."""
    other = env.client.post(
        "/v1/tenants", json={"slug": "other", "name": "Other"}, headers=OPERATOR
    ).json()
    scopes = ["runtime"] if request.param == "pinned_runtime_key" else [f"tenant:{other['id']}"]
    key = env.client.post(
        "/v1/api-keys",
        json={"name": "other-pep", "scopes": scopes, "tenant_id": other["id"]},
        headers=OPERATOR,
    ).json()["key"]
    return {"X-API-Key": key}


def _assert_forbidden(r) -> None:
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "tenant_scope_mismatch"


@pytest.mark.parametrize(
    "overrides",
    [
        {},  # everything exists
        {"agent_name": "profile:ghost"},
        {"user_ref": user_ref("nobody")},
        {"tenant_id": "no-such-tenant"},
    ],
    ids=["existing", "unknown_agent", "unknown_user", "unknown_tenant"],
)
def test_issue_grant_for_other_tenant_is_403_regardless_of_existence(
    env, other_tenant_caller, overrides
):
    body = {
        "tenant_id": TENANT,
        "application_id": "dtm",
        "user_ref": user_ref("ada"),
        "agent_name": AGENT,
        **overrides,
    }
    _assert_forbidden(env.client.post("/v1/delegations", json=body, headers=other_tenant_caller))


@pytest.mark.parametrize(
    "overrides",
    [
        {"application_id": "dtm", "agent_name": AGENT},
        {"application_id": "dtm", "agent_name": "profile:ghost"},
        {"application_id": "no-such-app", "agent_name": AGENT},
        {"user_ref": user_ref("nobody")},
        {"tenant_id": "no-such-tenant"},
    ],
    ids=["existing", "unknown_agent", "unknown_app", "unknown_user", "unknown_tenant"],
)
def test_revoke_for_other_tenant_is_403_regardless_of_existence(
    env, other_tenant_caller, overrides
):
    body = {"tenant_id": TENANT, **overrides}
    _assert_forbidden(
        env.client.post("/v1/delegations/revoke", json=body, headers=other_tenant_caller)
    )


@pytest.mark.parametrize("tenant", [TENANT, "no-such-tenant"], ids=["existing", "unknown"])
def test_tenant_roles_of_other_tenant_is_403_regardless_of_existence(
    env, other_tenant_caller, tenant
):
    _assert_forbidden(
        env.client.get(f"/v1/applications/dtm/tenants/{tenant}/roles", headers=other_tenant_caller)
    )


def test_unbound_runtime_caller_still_gets_404_for_unknown_references(env):
    r = env.client.post(
        "/v1/delegations",
        json={
            "tenant_id": "no-such-tenant",
            "application_id": "dtm",
            "user_ref": user_ref("ada"),
            "agent_name": AGENT,
        },
        headers=env.runtime,
    )
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "tenant_not_found"
    r = env.client.get("/v1/applications/dtm/tenants/no-such-tenant/roles", headers=env.runtime)
    assert r.status_code == 404
