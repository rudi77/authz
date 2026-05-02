"""Tests for the audit log retention helper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from authz_service.audit_retention import prune_audit_log
from authzkit.storage import orm
from authzkit.storage.sqlalchemy import (
    SqlAlchemyStore,
    create_engine_from_url,
    init_schema,
)


@pytest.fixture()
def store(temp_db_url) -> SqlAlchemyStore:
    engine = create_engine_from_url(temp_db_url)
    init_schema(engine)
    return SqlAlchemyStore(engine)


def _seed_old_and_new_rows(store: SqlAlchemyStore) -> None:
    now = datetime.now(UTC)

    with store.session() as s:
        # One fresh row.
        s.add(
            orm.AuditLog(
                decision="deny",
                resource="x",
                action="y",
                request={},
                response={},
                created_at=now,
            )
        )
        # Two old rows that should be pruned.
        for offset in (timedelta(days=10), timedelta(days=400)):
            s.add(
                orm.AuditLog(
                    decision="deny",
                    resource="x",
                    action="y",
                    request={},
                    response={},
                    created_at=now - offset,
                )
            )
        s.commit()


def test_prune_removes_only_rows_older_than_window(store: SqlAlchemyStore):
    _seed_old_and_new_rows(store)
    deleted = prune_audit_log(store, retention_days=7)
    assert deleted == 2
    from sqlalchemy import select

    with store.session() as s:
        remaining = s.scalars(select(orm.AuditLog)).all()
        assert len(remaining) == 1


def test_prune_no_op_when_disabled(store: SqlAlchemyStore):
    _seed_old_and_new_rows(store)
    deleted = prune_audit_log(store, retention_days=0)
    assert deleted == 0
    from sqlalchemy import select

    with store.session() as s:
        assert len(s.scalars(select(orm.AuditLog)).all()) == 3


def test_prune_idempotent_on_second_call(store: SqlAlchemyStore):
    _seed_old_and_new_rows(store)
    first = prune_audit_log(store, retention_days=7)
    second = prune_audit_log(store, retention_days=7)
    assert first == 2
    assert second == 0
