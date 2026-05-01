"""Pydantic request/response schemas shared by the service and SDKs."""

from authzkit.service.schemas import (
    AuthorizeRequestSchema,
    AuthorizeResponseSchema,
    BulkAuthorizeRequestSchema,
    BulkAuthorizeResponseSchema,
    BulkCheckResultSchema,
    BulkCheckSchema,
    EffectivePermissionsRequestSchema,
    EffectivePermissionsResponseSchema,
    ResolveContextRequestSchema,
    ResolveContextResponseSchema,
    SubjectSchema,
)

__all__ = [
    "AuthorizeRequestSchema",
    "AuthorizeResponseSchema",
    "BulkAuthorizeRequestSchema",
    "BulkAuthorizeResponseSchema",
    "BulkCheckResultSchema",
    "BulkCheckSchema",
    "EffectivePermissionsRequestSchema",
    "EffectivePermissionsResponseSchema",
    "ResolveContextRequestSchema",
    "ResolveContextResponseSchema",
    "SubjectSchema",
]
