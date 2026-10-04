"""Z-6: ``POST /v1/applications/{app}/claim-management`` re-takes management
after ``release-management`` (contract §5.8 item 6)."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from tests.integration._managed_env import OPERATOR, make_env


def test_claim_is_refused_while_someone_else_manages(temp_db_url):
    env = make_env(temp_db_url)
    r = env.client.post("/v1/applications/dtm/claim-management", headers=OPERATOR)
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == {
        "error": "application_managed_externally",
        "managed_by": env.manager_label,
    }


def test_manager_claiming_its_own_application_is_a_no_op(temp_db_url):
    env = make_env(temp_db_url)
    r = env.client.post("/v1/applications/dtm/claim-management", headers=env.manager)
    assert r.status_code == 200, r.text
    assert r.json()["managed_by"] == env.manager_label
    audit = env.client.get("/v1/audit", headers=OPERATOR).json()
    assert not [a for a in audit if a["reason"] == "management_claimed"]


def test_claim_after_release_sets_caller_and_is_audited(temp_db_url):
    env = make_env(temp_db_url)
    c = env.client
    app_id = c.get("/v1/applications/dtm", headers=OPERATOR).json()["id"]
    assert c.post("/v1/applications/dtm/release-management", headers=OPERATOR).status_code == 200

    r = c.post(f"/v1/applications/{app_id}/claim-management", headers=env.manager)
    assert r.status_code == 200, r.text
    assert r.json()["managed_by"] == env.manager_label
    assert c.get("/v1/applications/dtm", headers=OPERATOR).json()["managed_by"] == env.manager_label

    # Managed again: the operator is locked out of the application's data.
    r = c.post(f"/v1/applications/{app_id}/permissions", json={"name": "x.y"}, headers=OPERATOR)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "application_managed_externally"

    claimed = [a for a in c.get("/v1/audit", headers=OPERATOR).json() if a["reason"] == "management_claimed"]
    assert len(claimed) == 1
    assert claimed[0]["application_id"] == app_id
    assert claimed[0]["request"]["claimed_by"] == env.manager_label


def test_claim_needs_admin_scope_and_a_known_application(temp_db_url):
    env = make_env(temp_db_url)
    c = env.client
    assert c.post("/v1/applications/dtm/release-management", headers=OPERATOR).status_code == 200
    assert c.post("/v1/applications/dtm/claim-management", headers=env.runtime).status_code == 403
    r = c.post("/v1/applications/nope/claim-management", headers=OPERATOR)
    assert r.status_code == 404
    assert r.json()["detail"] == {"reason": "application_not_found"}
