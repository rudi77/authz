"""FastAPI integration helpers for applications using the SDK as a PEP."""

from __future__ import annotations

from typing import Annotated, Callable

try:
    from fastapi import Depends, HTTPException, status
except ImportError:  # pragma: no cover
    Depends = HTTPException = status = None  # type: ignore[assignment]

from authzkit.exceptions import PermissionDeniedError
from authz_sdk.client import AuthzClient, Subject


def require_permission(
    client_factory: Callable[[], AuthzClient],
    *,
    tenant_id_getter: Callable[..., str],
    application_id: str,
    user_id_getter: Callable[..., str],
    resource: str,
    action: str,
):
    """Build a FastAPI dependency that enforces a permission per request.

    The factory + getter pattern keeps the SDK from forcing apps into a
    particular client lifetime or auth header layout.
    """

    def _enforce(*args, **kwargs):
        client = client_factory()
        tenant_id = tenant_id_getter(*args, **kwargs)
        user_id = user_id_getter(*args, **kwargs)
        try:
            client.require(
                tenant_id=tenant_id,
                application_id=application_id,
                subject=Subject(type="user", user_id=user_id),
                resource=resource,
                action=action,
            )
        except PermissionDeniedError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"reason": "missing_permission", "permission": e.permission},
            )

    return _enforce
