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
class ResolvedReferences:
    """A decision's tenant / application / user / agent references, resolved
    by the store (``SqlAlchemyStore.resolve_references``) in one session.

    Passed to the engine, it replaces the engine's own reads of these rows.
    An unknown reference keeps the raw value (tenant, application) or ``None``
    (user, agent) and fails the engine's matching check, so the decision
    carries the engine's usual deny reason.
    """

    tenant_id: str  # resolved id, or the reference itself when unknown
    application_id: str
    tenant_status: str | None  # None: unknown reference
    application_status: str | None
    user_id: str | None = None  # given, or resolved from a user reference
    user_missing: bool = False  # a user reference matched nobody
    agent_id: str | None = None  # given, or resolved from the agent name
    agent_status: str | None = None  # set when resolved by name
    agent_missing: bool = False  # an agent name matched nothing

    @property
    def complete(self) -> bool:
        """Every reference matched a row."""
        return (
            self.tenant_status is not None
            and self.application_status is not None
            and not self.user_missing
            and not self.agent_missing
        )


@dataclass(frozen=True)
class AuthorizeRequest:
    tenant_id: str
    application_id: str
    subject: Subject
    resource: str
    action: str
    context: dict[str, Any] = field(default_factory=dict)
    # Permission subset from a verified delegation grant. ``None`` (default)
    # means no grant — the decision is exactly the pre-delegation behaviour.
    delegated_permissions: frozenset[str] | None = None
    references: ResolvedReferences | None = None


@dataclass(frozen=True)
class BulkAuthorizeRequest:
    tenant_id: str
    application_id: str
    subject: Subject
    checks: list[tuple[str, str]]  # [(resource, action), ...]
    context: dict[str, Any] = field(default_factory=dict)
    delegated_permissions: frozenset[str] | None = None
    references: ResolvedReferences | None = None


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

        inactive = self._inactive(request.tenant_id, request.application_id, request.references)
        if inactive is not None:
            return AuthorizeDecision.deny(inactive, required)

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
        undelegated = effective
        if request.delegated_permissions is not None:
            effective = effective & request.delegated_permissions

        if required not in effective:
            # The subject could do it, but the delegation grant doesn't cover it.
            if required in undelegated:
                return AuthorizeDecision.deny("not_delegated", required)
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
        inactive = self._inactive(request.tenant_id, request.application_id, request.references)
        if inactive is not None:
            return [AuthorizeDecision.deny(inactive, f"{r}.{a}") for r, a in request.checks]

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
        undelegated = effective
        if request.delegated_permissions is not None:
            effective = effective & request.delegated_permissions

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

            if required in undelegated:
                results.append(AuthorizeDecision.deny("not_delegated", required))
            elif (
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
            references=request.references,
        )
        if subject.type == SUBJECT_USER:
            result = self._resolve_user(marker)
        elif subject.type == SUBJECT_AGENT:
            result = self._resolve_agent(marker)
        else:
            return AuthorizeDecision.deny("invalid_subject", "_bulk._marker")
        return result

    def effective_permissions(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        delegated_permissions: frozenset[str] | None = None,
        references: ResolvedReferences | None = None,
    ) -> set[str]:
        """Return the set the subject can hit at this exact moment.

        Reflects tenant masks (and a delegation grant's subset, when given)
        but does not run ABAC — those are evaluated per-action because they
        depend on the resource attributes.
        """
        permissions = self._effective_permissions(
            tenant_id=tenant_id, application_id=application_id, subject=subject, refs=references
        )
        if delegated_permissions is not None:
            return permissions & delegated_permissions
        return permissions

    def _effective_permissions(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        refs: ResolvedReferences | None = None,
    ) -> set[str]:
        if self._inactive(tenant_id, application_id, refs) is not None:
            return set()

        if subject.type == SUBJECT_USER:
            if subject.user_id is None:
                return set()
            if not self._membership_active(tenant_id, application_id, subject.user_id, refs):
                return set()
            permissions = self.repository.resolve_user_permissions(
                tenant_id=tenant_id, application_id=application_id, user_id=subject.user_id
            )
        elif subject.type == SUBJECT_AGENT:
            if subject.user_id is None or subject.agent_id is None:
                return set()
            if not self._membership_active(tenant_id, application_id, subject.user_id, refs):
                return set()
            if not self._agent_active(tenant_id, application_id, subject.agent_id, refs):
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

    def _inactive(
        self, tenant_id: str, application_id: str, refs: ResolvedReferences | None
    ) -> str | None:
        """Deny reason for an inactive (or unknown) tenant / application."""
        if refs is None:
            if not self.repository.is_tenant_active(tenant_id):
                return "tenant_not_active"
            if not self.repository.is_application_active(application_id):
                return "application_not_active"
            return None
        if refs.tenant_status != "active":
            return "tenant_not_active"
        if refs.application_status != "active":
            return "application_not_active"
        return None

    def _membership_active(
        self, tenant_id: str, application_id: str, user_id: str, refs: ResolvedReferences | None
    ) -> bool:
        if refs is not None and refs.user_missing:
            return False  # user_id was filled in from a delegation grant
        return self.repository.is_user_membership_active(
            tenant_id=tenant_id, application_id=application_id, user_id=user_id
        )

    def _agent_active(
        self, tenant_id: str, application_id: str, agent_id: str, refs: ResolvedReferences | None
    ) -> bool:
        if refs is not None and refs.agent_missing:
            return False  # agent_id was filled in from a delegation grant
        if refs is not None and refs.agent_status is not None and agent_id == refs.agent_id:
            return refs.agent_status == "active"  # read while resolving the name
        return self.repository.is_agent_active(
            tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
        )

    def _resolve_user(self, request: AuthorizeRequest) -> set[str] | AuthorizeDecision:
        required = f"{request.resource}.{request.action}"
        refs = request.references
        user_id = request.subject.user_id
        if user_id is None and not (refs is not None and refs.user_missing):
            return AuthorizeDecision.deny("invalid_subject", required)
        if user_id is None or not self._membership_active(
            request.tenant_id, request.application_id, user_id, refs
        ):
            return AuthorizeDecision.deny("no_active_membership", required)
        if refs is not None and refs.agent_missing:
            return AuthorizeDecision.deny("agent_not_active", required)
        return self.repository.resolve_user_permissions(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=user_id,
        )

    def _resolve_agent(self, request: AuthorizeRequest) -> set[str] | AuthorizeDecision:
        required = f"{request.resource}.{request.action}"
        refs = request.references
        user_id, agent_id = request.subject.user_id, request.subject.agent_id
        # A reference that matched nothing still names the user / agent.
        if (user_id is None and not (refs is not None and refs.user_missing)) or (
            agent_id is None and not (refs is not None and refs.agent_missing)
        ):
            return AuthorizeDecision.deny("invalid_subject", required)
        if user_id is None or not self._membership_active(
            request.tenant_id, request.application_id, user_id, refs
        ):
            return AuthorizeDecision.deny("no_active_user_membership", required)
        if agent_id is None or not self._agent_active(
            request.tenant_id, request.application_id, agent_id, refs
        ):
            return AuthorizeDecision.deny("agent_not_active", required)
        user_perms = self.repository.resolve_user_permissions(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=user_id,
        )
        agent_perms = self.repository.resolve_agent_permissions(
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            agent_id=agent_id,
        )
        # An agent never gets more than the user (spec section 2.5).
        return user_perms & agent_perms
