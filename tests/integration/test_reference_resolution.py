"""Decision references resolve in authzkit: one session, then the engine.

``SqlAlchemyStore.resolve_references`` turns tenant/application (id or slug),
``user_ref`` and ``agent_name`` into ids in a single session. The engine takes
the result: rows already read there (tenant, application, agent by name) are
not read again, and unknown references end in the engine's own deny reasons.
"""

from __future__ import annotations

import pytest
from sqlalchemy import event

from authzkit.provisioning import UserRef
from authzkit.rbac.checker import (
    SUBJECT_AGENT,
    SUBJECT_USER,
    AuthorizationEngine,
    AuthorizeRequest,
    BulkAuthorizeRequest,
    Subject,
)
from authzkit.rbac.models import RoleScope
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

ADA = UserRef("dtm", "urn:dtm:test", "ada")
NOBODY = UserRef("dtm", "urn:dtm:test", "nobody")


@pytest.fixture()
def store(temp_db_url):
    engine = create_engine_from_url(temp_db_url)
    init_schema(engine)
    yield SqlAlchemyStore(engine)
    engine.dispose()


@pytest.fixture()
def world(store):
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="dtm", name="DTM")
    store.create_permission(name="docs.read", application_id=app.id)
    role = store.create_role(name="reader", scope=RoleScope.APPLICATION, application_id=app.id)
    store.set_role_permissions(role.id, {"docs.read"})
    user, _ = store.upsert_user_from_identity(
        provider=ADA.provider, issuer=ADA.issuer, subject=ADA.subject, email=None,
        external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id, roles={"reader"}
    )
    agent = store.create_agent(tenant_id=tenant.id, application_id=app.id, name="bot")
    store.set_agent_roles(agent.id, {"reader"})
    return {"tenant": tenant, "app": app, "user": user, "agent": agent}


class _Counter:
    def __init__(self, store: SqlAlchemyStore) -> None:
        self.checkouts = 0
        self.statements: list[str] = []
        event.listen(store.engine, "checkout", self._checkout)
        event.listen(store.engine, "before_cursor_execute", self._execute)

    def _checkout(self, *args) -> None:
        self.checkouts += 1

    def _execute(self, conn, cursor, statement, *args) -> None:
        self.statements.append(statement)


def test_references_resolve_in_one_session(store, world):
    counter = _Counter(store)
    refs = store.resolve_references(
        tenant="acme", application="dtm", user_ref=ADA, agent_name="bot"
    )
    assert counter.checkouts == 1
    assert len(counter.statements) == 4  # tenant, application, user, agent
    assert refs.tenant_id == world["tenant"].id
    assert refs.application_id == world["app"].id
    assert refs.user_id == world["user"].id
    assert refs.agent_id == world["agent"].id
    assert refs.complete


def test_ids_and_slugs_both_resolve(store, world):
    by_id = store.resolve_references(tenant=world["tenant"].id, application=world["app"].id)
    by_slug = store.resolve_references(tenant="acme", application="dtm")
    assert (by_id.tenant_id, by_id.application_id) == (by_slug.tenant_id, by_slug.application_id)


def test_given_ids_pass_through_unread(store, world):
    counter = _Counter(store)
    refs = store.resolve_references(
        tenant="acme",
        application="dtm",
        user_id=world["user"].id,
        agent_id=world["agent"].id,
    )
    assert len(counter.statements) == 2  # tenant, application
    assert (refs.user_id, refs.agent_id) == (world["user"].id, world["agent"].id)


def test_engine_does_not_reread_resolved_rows(store, world):
    refs = store.resolve_references(tenant="acme", application="dtm", user_ref=ADA, agent_name="bot")
    engine = AuthorizationEngine(store)
    counter = _Counter(store)
    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=refs.tenant_id,
            application_id=refs.application_id,
            subject=Subject(type=SUBJECT_AGENT, user_id=refs.user_id, agent_id=refs.agent_id),
            resource="docs",
            action="read",
            references=refs,
        )
    )
    assert decision.allowed, decision
    read = " ".join(counter.statements)
    assert "FROM tenants" not in read
    assert "FROM applications" not in read
    # Only the permission resolution reads the agent; its status came with the name.
    assert read.count("FROM agents") == 1


@pytest.mark.parametrize(
    ("kwargs", "subject_type", "reason"),
    [
        ({"tenant": "nope"}, SUBJECT_USER, "tenant_not_active"),
        ({"application": "nope"}, SUBJECT_USER, "application_not_active"),
        ({"user_ref": NOBODY}, SUBJECT_USER, "no_active_membership"),
        ({"user_ref": NOBODY, "agent_name": "bot"}, SUBJECT_AGENT, "no_active_user_membership"),
        ({"user_ref": ADA, "agent_name": "ghost"}, SUBJECT_AGENT, "agent_not_active"),
    ],
)
def test_unknown_references_get_the_engines_deny_reason(store, world, kwargs, subject_type, reason):
    args = {"tenant": "acme", "application": "dtm", "user_ref": ADA, **kwargs}
    refs = store.resolve_references(**args)
    assert not refs.complete
    subject = Subject(type=subject_type, user_id=refs.user_id, agent_id=refs.agent_id)
    engine = AuthorizationEngine(store)
    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=refs.tenant_id,
            application_id=refs.application_id,
            subject=subject,
            resource="docs",
            action="read",
            references=refs,
        )
    )
    assert (decision.allowed, decision.reason) == (False, reason)
    bulk = engine.bulk_authorize(
        BulkAuthorizeRequest(
            tenant_id=refs.tenant_id,
            application_id=refs.application_id,
            subject=subject,
            checks=[("docs", "read")],
            references=refs,
        )
    )
    assert [d.reason for d in bulk] == [reason]
    assert engine.effective_permissions(
        tenant_id=refs.tenant_id,
        application_id=refs.application_id,
        subject=subject,
        references=refs,
    ) == set()
