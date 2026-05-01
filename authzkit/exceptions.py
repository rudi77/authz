"""Exception hierarchy for authzkit.

Reason codes follow the spec in section 17.
"""

from __future__ import annotations


class AuthzError(Exception):
    """Base class for all authzkit exceptions."""

    reason: str = "authz_error"


class InvalidRequestError(AuthzError):
    reason = "invalid_request"


class InvalidSubjectError(AuthzError):
    reason = "invalid_subject"


class TenantNotActiveError(AuthzError):
    reason = "tenant_not_active"


class ApplicationNotActiveError(AuthzError):
    reason = "application_not_active"


class NoActiveMembershipError(AuthzError):
    reason = "no_active_membership"


class AgentNotFoundError(AuthzError):
    reason = "agent_not_found"


class AgentNotActiveError(AuthzError):
    reason = "agent_not_active"


class TenantFeatureDisabledError(AuthzError):
    reason = "tenant_feature_disabled"


class PolicyConditionFailedError(AuthzError):
    reason = "policy_condition_failed"


class PermissionDeniedError(AuthzError):
    """Raised by ToolGuard / MCPGuard when a permission is missing."""

    reason = "missing_permission"

    def __init__(self, permission: str, message: str | None = None) -> None:
        self.permission = permission
        super().__init__(message or f"Permission denied: {permission}")
