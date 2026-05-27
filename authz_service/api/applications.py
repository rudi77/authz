"""Application management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authz_service.dependencies import get_store, require_admin
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
