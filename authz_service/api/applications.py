"""Application management endpoints."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import select

from authz_service.config import Settings, get_settings
from authz_service.dependencies import get_store, require_admin
from authz_service.management import caller_label, managed_externally
from authz_service.references import require_application
from authzkit.audit.logger import AuditEntry
from authzkit.security.principal import Principal
from authzkit.storage import orm
from authzkit.storage.sqlalchemy import SqlAlchemyStore

_log = logging.getLogger("authz.applications")

router = APIRouter(prefix="/v1/applications", tags=["applications"])


class ApplicationIn(BaseModel):
    slug: str
    name: str
    status: str = "active"


class ApplicationOut(BaseModel):
    """Routes serve this with ``response_model_exclude_defaults`` so a null
    ``managed_by`` is omitted and older SDKs (strict dataclasses) keep working."""

    id: str
    slug: str
    name: str
    status: str
    managed_by: str | None = None


class ApplicationPatch(BaseModel):
    name: str | None = None
    status: str | None = None


@router.post(
    "",
    response_model=ApplicationOut,
    response_model_exclude_defaults=True,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_application(
    body: ApplicationIn, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> ApplicationOut:
    app = store.create_application(slug=body.slug, name=body.name, status=body.status)
    return ApplicationOut(id=app.id, slug=app.slug, name=app.name, status=app.status)


@router.get(
    "",
    response_model=list[ApplicationOut],
    response_model_exclude_defaults=True,
    dependencies=[Depends(require_admin)],
)
def list_applications(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    page: int = 1,
    page_size: int = 100,
) -> list[ApplicationOut]:
    from authz_service.middleware import paginate_params

    offset, limit = paginate_params(page, page_size)
    with store.session() as s:
        rows = s.scalars(
            select(orm.Application).order_by(orm.Application.slug).offset(offset).limit(limit)
        ).all()
        return [
            ApplicationOut(
                id=r.id, slug=r.slug, name=r.name, status=r.status, managed_by=r.managed_by
            )
            for r in rows
        ]


@router.get(
    "/{application_id}",
    response_model=ApplicationOut,
    response_model_exclude_defaults=True,
    dependencies=[Depends(require_admin)],
)
def get_application(
    application_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> ApplicationOut:
    app = require_application(store, application_id)
    return ApplicationOut(
        id=app.id, slug=app.slug, name=app.name, status=app.status, managed_by=app.managed_by
    )


@router.patch(
    "/{application_id}",
    response_model=ApplicationOut,
    response_model_exclude_defaults=True,
    dependencies=[Depends(require_admin)],
)
def update_application(
    application_id: str,
    body: ApplicationPatch,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> ApplicationOut:
    app = require_application(store, application_id)
    with store.session() as s:
        row = s.get(orm.Application, app.id)
        if body.name is not None:
            row.name = body.name
        if body.status is not None:
            row.status = body.status
        s.commit()
        return ApplicationOut(
            id=row.id, slug=row.slug, name=row.name, status=row.status, managed_by=app.managed_by
        )


@router.post("/{application_id}/release-management", response_model=ApplicationOut)
def release_management(
    application_id: str,
    principal: Annotated[Principal, Depends(require_admin)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ApplicationOut:
    """Emergency exit: drop ``managed_by`` so platform admins can write again."""
    app = require_application(store, application_id)
    released_by = caller_label(principal, settings)
    store.set_application_managed_by(app.id, None)
    store.write_audit(
        AuditEntry(
            decision="admin",
            reason="management_released",
            resource="application.management",
            action="release",
            application_id=app.id,
            request={"managed_by": app.managed_by, "released_by": released_by},
            response={"managed_by": None},
        )
    )
    _log.warning(
        "management of application %s released by %s (was %s)",
        app.slug,
        released_by,
        app.managed_by,
    )
    return ApplicationOut(id=app.id, slug=app.slug, name=app.name, status=app.status)


@router.post(
    "/{application_id}/claim-management",
    response_model=ApplicationOut,
    response_model_exclude_defaults=True,
)
def claim_management(
    application_id: str,
    principal: Annotated[Principal, Depends(require_admin)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ApplicationOut:
    """Make the caller the manager of an unmanaged application (after
    ``release-management``). 409 while someone else manages it."""
    app = require_application(store, application_id)
    claimed_by = caller_label(principal, settings)
    if app.managed_by is None:
        managed_by = store.claim_application_management(app.id, claimed_by)
        if managed_by == claimed_by:
            store.write_audit(
                AuditEntry(
                    decision="admin",
                    reason="management_claimed",
                    resource="application.management",
                    action="claim",
                    application_id=app.id,
                    request={"claimed_by": claimed_by},
                    response={"managed_by": claimed_by},
                )
            )
            _log.warning("management of application %s claimed by %s", app.slug, claimed_by)
    else:
        managed_by = app.managed_by
    if managed_by != claimed_by:
        raise managed_externally(managed_by or "", status.HTTP_409_CONFLICT)
    return ApplicationOut(
        id=app.id, slug=app.slug, name=app.name, status=app.status, managed_by=managed_by
    )
