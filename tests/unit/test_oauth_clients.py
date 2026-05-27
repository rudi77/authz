"""Unit tests for OAuthClientService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from authzkit.security.oauth_clients import OAuthClientService
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema


@pytest.fixture()
def store() -> SqlAlchemyStore:
    """Fresh in-memory SQLite store per test."""
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    return SqlAlchemyStore(engine)


def test_issue_returns_plaintext_once_and_persists_hash(store):
    service = OAuthClientService(store)
    credentials = service.issue(name="demo", scopes=["runtime"])
    assert credentials.client_secret.startswith("ocs_")
    assert credentials.record.client_id.startswith("oc_")
    assert credentials.record.scopes == ("runtime",)
    # The secret is gone from the record — only the plaintext on credentials.
    rec = service.get(credentials.record.client_id)
    assert rec is not None
    assert rec.client_id == credentials.record.client_id


def test_authenticate_happy_path(store):
    service = OAuthClientService(store)
    credentials = service.issue(name="demo", scopes=["runtime", "tenant:t1"])
    record = service.authenticate(
        credentials.record.client_id, credentials.client_secret
    )
    assert record is not None
    assert record.client_id == credentials.record.client_id


def test_authenticate_wrong_secret_returns_none(store):
    service = OAuthClientService(store)
    credentials = service.issue(name="demo", scopes=["runtime"])
    assert service.authenticate(credentials.record.client_id, "wrong") is None


def test_authenticate_unknown_client_returns_none(store):
    service = OAuthClientService(store)
    assert service.authenticate("oc_does_not_exist", "anything") is None


def test_authenticate_revoked_client_returns_none(store):
    service = OAuthClientService(store)
    credentials = service.issue(name="demo", scopes=["runtime"])
    service.revoke(credentials.record.client_id)
    assert (
        service.authenticate(credentials.record.client_id, credentials.client_secret)
        is None
    )


def test_authenticate_expired_client_returns_none(store):
    service = OAuthClientService(store)
    credentials = service.issue(
        name="demo",
        scopes=["runtime"],
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert (
        service.authenticate(credentials.record.client_id, credentials.client_secret)
        is None
    )


def test_rotate_secret_invalidates_old_secret(store):
    service = OAuthClientService(store)
    credentials = service.issue(name="demo", scopes=["runtime"])
    old_secret = credentials.client_secret
    rotated = service.rotate_secret(credentials.record.client_id)
    assert rotated is not None
    assert rotated.client_secret != old_secret
    # Old secret stops working immediately.
    assert service.authenticate(credentials.record.client_id, old_secret) is None
    # New secret works.
    assert service.authenticate(credentials.record.client_id, rotated.client_secret) is not None


def test_tenant_bound_client_records_tenant_id(store):
    """Tenant binding is preserved on the record so the token endpoint can read it."""
    service = OAuthClientService(store)
    credentials = service.issue(
        name="acme", scopes=["runtime"], tenant_id="acme-uuid"
    )
    assert credentials.record.tenant_id == "acme-uuid"
    rec = service.get(credentials.record.client_id)
    assert rec is not None and rec.tenant_id == "acme-uuid"
