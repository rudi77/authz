"""Pydantic schemas mirroring the REST API in spec section 10.

Kept inside :mod:`authzkit` so SDKs and the service share identical types.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


def one_form(a: object, b: object, names: str, *, required: bool = False) -> None:
    """At most one (``required``: exactly one) of two alternative fields,
    e.g. ``user_id`` / ``user_ref``. Raise from a model validator (→ 422)."""
    if a is not None and b is not None:
        raise ValueError(f"give {names}, not both")
    if required and a is None and b is None:
        raise ValueError(f"give {names}")


class UserRefSchema(_Base):
    """A user by identity at its IdP instead of the authz user id."""

    provider: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    subject: str = Field(min_length=1)


class SubjectSchema(_Base):
    type: str = Field(description="user | agent | service_account | api_key")
    user_id: str | None = None
    user_ref: UserRefSchema | None = Field(
        default=None, description="Alternative to user_id: the user's IdP identity"
    )
    agent_id: str | None = None
    agent_name: str | None = Field(
        default=None, description="Alternative to agent_id: the agent's name in the tenant"
    )
    service_account_id: str | None = None

    @model_validator(mode="after")
    def _one_form_per_reference(self) -> SubjectSchema:
        one_form(self.user_id, self.user_ref, "user_id or user_ref")
        one_form(self.agent_id, self.agent_name, "agent_id or agent_name")
        return self


# ---- /v1/resolve-context ----------------------------------------------------


class ResolveContextRequestSchema(_Base):
    application_id: str = Field(description="Application slug or id")
    provider: str
    issuer: str
    subject: str
    email: str | None = None
    external_tenant_id: str | None = None
    explicit_tenant_id: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)


class ResolveContextResponseSchema(_Base):
    tenant_id: str
    application_id: str
    user_id: str
    roles: list[str]
    permissions: list[str]


# ---- /v1/authorize ----------------------------------------------------------


class AuthorizeRequestSchema(_Base):
    tenant_id: str
    application_id: str
    subject: SubjectSchema
    resource: str
    action: str
    context: dict[str, Any] = Field(default_factory=dict)


class AuthorizeResponseSchema(_Base):
    allowed: bool
    decision: str
    reason: str
    required_permission: str
    matched_permissions: list[str] = Field(default_factory=list)


# ---- /v1/bulk-authorize -----------------------------------------------------


class BulkCheckSchema(_Base):
    resource: str
    action: str


class BulkAuthorizeRequestSchema(_Base):
    tenant_id: str
    application_id: str
    subject: SubjectSchema
    checks: list[BulkCheckSchema]
    context: dict[str, Any] = Field(default_factory=dict)


class BulkCheckResultSchema(_Base):
    resource: str
    action: str
    allowed: bool
    reason: str


class BulkAuthorizeResponseSchema(_Base):
    results: list[BulkCheckResultSchema]


# ---- /v1/effective-permissions ----------------------------------------------


class EffectivePermissionsRequestSchema(_Base):
    tenant_id: str
    application_id: str
    subject: SubjectSchema


class EffectivePermissionsResponseSchema(_Base):
    tenant_id: str
    application_id: str
    subject: SubjectSchema
    permissions: list[str]
