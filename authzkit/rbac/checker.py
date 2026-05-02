"""AuthorizationEngine — central Policy Decision Point.

Implements the algorithms in spec section 11. Tenant feature flags acting as
permission masks are applied last so they can hard-deny without requiring
domain code to know about them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from authzkit.policies.engine import PolicyEngine
from authzkit.rbac.repository import RBACRepository

SUBJECT_USER = "user"
SUBJECT_AGENT = "agent"
SUBJECT_SERVICE_ACCOUNT = "service_account"
SUBJECT_API_KEY = "api_key"


@dataclass(frozen=True)
class Subject:
    """Who is acting. ``type`` selects the algorithm branch."""

    type: str
    user_id: str | None = None
    agent_id: str | None = None
    service_account_id: str | None = None


@dataclass(frozen=True)
class AuthorizeRequest:
    tenant_id: str
    application_id: str
    subject: Subject
    resource: str
    action: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BulkAuthorizeRequest:
    tenant_id: str
    application_id: str
    subject: Subject
    checks: list[tuple[str, str]]  # [(resource, action), ...]
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthorizeDecision:
    allowed: bool
    decision: str  # "allow" | "deny"
    reason: str
    required_permission: str
    matched_permissions: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def allow(
        cls, required: str, matched: frozenset[str] | set[str] | None = None
    ) -> AuthorizeDecision:
        m = frozenset(matched or {required})
        return cls(True, "allow", "permission_granted", required, m)

    @classmethod
    def deny(cls, reason: str, required: str) -> AuthorizeDecision:
        return cls(False, "deny", reason, required, frozenset())


class AuthorizationEngine:
    """Central PDP. Stateless across requests; all state lives in repositories."""

    def __init__(
        self,
        repository: RBACRepository,
        *,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.repository = repository
        self.policy_engine = policy_engine or PolicyEngine()

    def authorize(self, request: AuthorizeRequest) -> AuthorizeDecision:
        required = f"{request.resource}.{request.action}"

        if not self.repository.is_tenant_active(request.tenant_id):
            return AuthorizeDecision.deny("tenant_not_active", required)
        if not self.repository.is_application_active(request.application_id):
            return AuthorizeDecision.deny("application_not_active", required)

        if request.subject.type == SUBJECT_USER:
            permissions = self._resolve_user(request)
        elif request.subject.type == SUBJECT_AGENT:
            permissions = self._resolve_agent(request)
            if isinstance(permissions, AuthorizeDecision):
                return permissions
        else:
            return AuthorizeDecision.deny("invalid_subject", required)

        if isinstance(permissions, AuthorizeDecision):
            return permissions

        tenant_permissions = self.repository.resolve_tenant_permissions(
            tenant_id=request.tenant_id, application_id=request.application_id
        )
        # Empty tenant mask = unrestricted, otherwise tenant masks the result.
        # An explicit empty mask configured for a tenant must use the sentinel
        # permission set that's still non-empty; we treat None-equivalent as
        # "no mask configured."
        effective = permissions & tenant_permissions if tenant_permissions else permissions

        if required not in effective:
            # Disambiguate: was it a tenant-feature mask, or just missing perm?
            if (
                tenant_permissions
                and required in permissions
                and required not in tenant_permissions
            ):
                return AuthorizeDecision.deny("tenant_feature_disabled", required)
            return AuthorizeDecision.deny("missing_permission", required)

        if not self.policy_engine.evaluate(request, effective):
            return AuthorizeDecision.deny("policy_condition_failed", required)

        return AuthorizeDecision.allow(required, {required})

    def bulk_authorize(self, request: BulkAuthorizeRequest) -> list[AuthorizeDecision]:
        """Evaluate many checks against the same subject in one pass.

        Resolves the subject's permission set *once* and reuses it for every
        check. Drops the per-check from O(N) DB queries to O(1) for the hot
        path where an agent runtime asks "which of these N tools can I call?".
        """
        # Tenant + application activity: single check up front. If either is
        # inactive, every result is the same deny reason.
        if not self.repository.is_tenant_active(request.tenant_id):
            return [
                AuthorizeDecision.deny("tenant_not_active", f"{r}.{a}")
                for r, a in request.checks
            ]
        if not self.repository.is_application_active(request.application_id):
            return [
                AuthorizeDecision.deny("application_not_active", f"{r}.{a}")
                for r, a in request.checks
            ]

        # Resolve the subject's permission set once.
        subject_perms = self._subject_permissions_or_deny(request.subject, request)
        if isinstance(subject_perms, AuthorizeDecision):
            # Subject-level deny (e.g. inactive membership). Spread the same
            # reason across every check so callers get a uniform response shape.
            return [
                AuthorizeDecision.deny(subject_perms.reason, f"{r}.{a}")
                for r, a in request.checks
            ]

        tenant_permissions = self.repository.resolve_tenant_permissions(
            tenant_id=request.tenant_id, application_id=request.application_id
        )
        effective = subject_perms & tenant_permissions if tenant_permissions else subject_perms

        results: list[AuthorizeDecision] = []
        for resource, action in request.checks:
            required = f"{resource}.{action}"
            if required in effective:
                # Per-check ABAC still needs to run because conditions can
                # depend on resource attributes.
                if not self.policy_engine.evaluate(
                    AuthorizeRequest(
                        tenant_id=request.tenant_id,
                        application_id=request.application_id,
                        subject=request.subject,
                        resource=resource,
                        action=action,
                        context=request.context,
                    ),
                    effective,
                ):
                    results.append(
                        AuthorizeDecision.deny("policy_condition_failed", required)
                    )
                    continue
                results.append(AuthorizeDecision.allow(required, {required}))
                continue

            if (
                tenant_permissions
                and required in subject_perms
                and required not in tenant_permissions
            ):
                results.append(
                    AuthorizeDecision.deny("tenant_feature_disabled", required)
                )
            else:
                results.append(AuthorizeDecision.deny("missing_permission", required))
        return results

    def _subject_permissions_or_deny(
        self, subject: Subject, request: BulkAuthorizeRequest
    ) -> set[str] | AuthorizeDecision:
        """Resolve the bare permission set for a subject without tenant masking."""
        marker = AuthorizeRequest(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            subject=subject,
            resource="_bulk",
            action="_marker",
        )
        if subject.type == SUBJECT_USER:
            result = self._resolve_user(marker)
        elif subject.type == SUBJECT_AGENT:
            result = self._resolve_agent(marker)
        else:
            return AuthorizeDecision.deny("invalid_subject", "_bulk._marker")
        return result

    def effective_permissions(
        self, *, tenant_id: str, application_id: str, subject: Subject
    ) -> set[str]:
        """Return the set the subject can hit at this exact moment.

        Reflects tenant masks but does not run ABAC — those are evaluated
        per-action because they depend on the resource attributes.
        """
        if not self.repository.is_tenant_active(tenant_id):
            return set()
        if not self.repository.is_application_active(application_id):
            return set()

        if subject.type == SUBJECT_USER:
            if subject.user_id is None:
                return set()
            if not self.repository.is_user_membership_active(
                tenant_id=tenant_id, application_id=application_id, user_id=subject.user_id
            ):
                return set()
            permissions = self.repository.resolve_user_permissions(
                tenant_id=tenant_id, application_id=application_id, user_id=subject.user_id
            )
        elif subject.type == SUBJECT_AGENT:
            if subject.user_id is None or subject.agent_id is None:
                return set()
            if not self.repository.is_user_membership_active(
                tenant_id=tenant_id, application_id=application_id, user_id=subject.user_id
            ):
                return set()
            if not self.repository.is_agent_active(
                tenant_id=tenant_id, application_id=application_id, agent_id=subject.agent_id
            ):
                return set()
            user_perms = self.repository.resolve_user_permissions(
                tenant_id=tenant_id, application_id=application_id, user_id=subject.user_id
            )
            agent_perms = self.repository.resolve_agent_permissions(
                tenant_id=tenant_id, application_id=application_id, agent_id=subject.agent_id
            )
            permissions = user_perms & agent_perms
        else:
            return set()

        tenant_permissions = self.repository.resolve_tenant_permissions(
            tenant_id=tenant_id, application_id=application_id
        )
        if tenant_permissions:
            return permissions & tenant_permissions
        return permissions

    # ---- internal branches ---------------------------------------------------

    def _resolve_user(self, request: AuthorizeRequest) -> set[str] | AuthorizeDecision:
        required = f"{request.resource}.{request.action}"
        if request.subject.user_id is None:
            return AuthorizeDecision.deny("invalid_subject", required)
        if not self.repository.is_user_membership_active(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=request.subject.user_id,
        ):
            return AuthorizeDecision.deny("no_active_membership", required)
        return self.repository.resolve_user_permissions(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=request.subject.user_id,
        )

    def _resolve_agent(self, request: AuthorizeRequest) -> set[str] | AuthorizeDecision:
        required = f"{request.resource}.{request.action}"
        if request.subject.user_id is None or request.subject.agent_id is None:
            return AuthorizeDecision.deny("invalid_subject", required)
        if not self.repository.is_user_membership_active(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=request.subject.user_id,
        ):
            return AuthorizeDecision.deny("no_active_user_membership", required)
        if not self.repository.is_agent_active(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            agent_id=request.subject.agent_id,
        ):
            return AuthorizeDecision.deny("agent_not_active", required)
        user_perms = self.repository.resolve_user_permissions(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=request.subject.user_id,
        )
        agent_perms = self.repository.resolve_agent_permissions(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            agent_id=request.subject.agent_id,
        )
        # An agent never gets more than the user (spec section 2.5).
        return user_perms & agent_perms
