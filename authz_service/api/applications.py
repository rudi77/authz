"""Application management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from authz_service.dependencies import get_store, require_admin
from authzkit.storage import orm
from authzkit.storage.sqlalchemy import SqlAlchemyStore

router = APIRouter(prefix="/v1/applications", tags=["applications"])


class ApplicationIn(BaseModel):
    slug: str
    name: str
    status: str = "active"


class ApplicationOut(BaseModel):
    id: str
    slug: str
    name: str
    status: str


class ApplicationPatch(BaseModel):
    name: str | None = None
    status: str | None = None


@router.post(
    "",
    response_model=ApplicationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_application(
    body: ApplicationIn, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> ApplicationOut:
    app = store.create_application(slug=body.slug, name=body.name, status=body.status)
    return ApplicationOut(id=app.id, slug=app.slug, name=app.name, status=app.status)


@router.get("", response_model=list[ApplicationOut], dependencies=[Depends(require_admin)])
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
            ApplicationOut(id=r.id, slug=r.slug, name=r.name, status=r.status) for r in rows
        ]


@router.get(
    "/{application_id}", response_model=ApplicationOut, dependencies=[Depends(require_admin)]
)
def get_application(
    application_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> ApplicationOut:
    app = store.get_application(application_id) or store.get_application_by_slug(application_id)
    if app is None:
        raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
    return ApplicationOut(id=app.id, slug=app.slug, name=app.name, status=app.status)


@router.patch(
    "/{application_id}", response_model=ApplicationOut, dependencies=[Depends(require_admin)]
)
def update_application(
    application_id: str,
    body: ApplicationPatch,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> ApplicationOut:
    app = store.get_application(application_id) or store.get_application_by_slug(application_id)
    if app is None:
        raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
    with store.session() as s:
        row = s.get(orm.Application, app.id)
        if body.name is not None:
            row.name = body.name
        if body.status is not None:
            row.status = body.status
        s.commit()
        return ApplicationOut(id=row.id, slug=row.slug, name=row.name, status=row.status)
