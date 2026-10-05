"""HTTP client for the AuthZ Service.

Provides a synchronous interface backed by httpx. Includes a small bounded
LRU cache for ``effective_permissions`` because that's the hot path for
agent runs (spec section 14).
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from authzkit.exceptions import PermissionDeniedError

DELEGATION_HEADER = "X-Delegation-Token"


class AuthzClientError(Exception):
    """Base error for SDK-level problems (transport, validation)."""


class AuthzServiceError(AuthzClientError):
    """Raised when the AuthZ service returns a non-success status code."""

    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"AuthZ service returned {status_code}: {body}")


@dataclass(frozen=True)
class UserRef:
    """A user by IdP identity — an alternative to the authz ``user_id``."""

    provider: str
    issuer: str
    subject: str

    def to_dict(self) -> dict[str, str]:
        return {"provider": self.provider, "issuer": self.issuer, "subject": self.subject}


@dataclass(frozen=True)
class Subject:
    """Who acts. ``user_ref`` / ``agent_name`` are alternatives to the ids;
    the service resolves them (give one form per field)."""

    type: str  # "user" | "agent"
    user_id: str | None = None
    agent_id: str | None = None
    service_account_id: str | None = None
    user_ref: UserRef | None = None
    agent_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type}
        if self.user_id is not None:
            out["user_id"] = self.user_id
        if self.agent_id is not None:
            out["agent_id"] = self.agent_id
        if self.service_account_id is not None:
            out["service_account_id"] = self.service_account_id
        if self.user_ref is not None:
            out["user_ref"] = self.user_ref.to_dict()
        if self.agent_name is not None:
            out["agent_name"] = self.agent_name
        return out


@dataclass(frozen=True)
class BulkCheck:
    resource: str
    action: str


@dataclass(frozen=True)
class BulkCheckResult:
    resource: str
    action: str
    allowed: bool
    reason: str


@dataclass(frozen=True)
class AuthorizeResult:
    """Structured result of an ``/v1/authorize`` decision.

    Mirrors :class:`authzkit.service.schemas.AuthorizeResponseSchema` so
    PEP integrations (e.g. taskforce-enterprise's ``AuthzPolicyEngine``)
    can audit ``reason`` / ``required_permission`` instead of squinting
    at a bare boolean.
    """

    allowed: bool
    decision: str
    reason: str
    required_permission: str
    matched_permissions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ResolvedContext:
    tenant_id: str
    application_id: str
    user_id: str
    roles: frozenset[str]
    permissions: frozenset[str]


@dataclass(frozen=True)
class Delegation:
    """A delegation grant. ``token`` is only set on the issuance response."""

    id: str
    tenant_id: str
    application_id: str
    user_id: str
    agent_id: str
    permissions: frozenset[str]
    status: str
    active: bool
    expires_at: datetime
    purpose: str | None = None
    token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Delegation:
        return cls(
            id=data["id"],
            tenant_id=data["tenant_id"],
            application_id=data["application_id"],
            user_id=data["user_id"],
            agent_id=data["agent_id"],
            permissions=frozenset(data.get("permissions") or ()),
            status=data.get("status", "active"),
            active=bool(data.get("active", True)),
            expires_at=datetime.fromisoformat(str(data["expires_at"]).replace("Z", "+00:00")),
            purpose=data.get("purpose"),
            token=data.get("token"),
        )


def _delegation_headers(token: str | None) -> dict[str, str] | None:
    return {DELEGATION_HEADER: token} if token else None


@dataclass
class _CacheEntry:
    permissions: set[str]
    expires_at: float


class AuthzClient:
    """Sync client for the AuthZ Service.

    Why sync: the spec is explicit that the service is the PDP and the app is
    the PEP. PEP calls happen at request boundaries, where blocking is fine
    and matches the surrounding request handler's threading model.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = 5.0,
        cache_ttl_seconds: float = 0.0,
        cache_max_entries: int = 1024,
        transport: httpx.BaseTransport | None = None,
        http_client: httpx.Client | None = None,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.1,
    ) -> None:
        if not base_url.endswith("/"):
            base_url = base_url + "/"
        if http_client is not None:
            # Tests pass FastAPI's TestClient here so the SDK can drive an
            # in-process app without a real socket. We still set our headers
            # via per-request hook because the caller may use the client too.
            self._http = http_client
            self._owns_http = False
            if api_key:
                self._http.headers["X-API-Key"] = api_key
        else:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if api_key:
                headers["X-API-Key"] = api_key
            self._http = httpx.Client(
                base_url=base_url,
                timeout=timeout,
                headers=headers,
                transport=transport,
            )
            self._owns_http = True
        self._cache_ttl = cache_ttl_seconds
        self._cache_max_entries = cache_max_entries
        self._cache: OrderedDict[tuple[str, str, str], _CacheEntry] = OrderedDict()
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff_seconds

    def __enter__(self) -> AuthzClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    # ---- HTTP helper ---------------------------------------------------------

    def _post(self, path: str, body: dict, headers: dict[str, str] | None = None) -> dict:
        return self._request("POST", path, body, headers)

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        attempts = 0
        last_exc: Exception | None = None
        while attempts <= self._max_retries:
            try:
                response = self._http.request(
                    method, path, json=body, headers=headers, params=params
                )
            except httpx.HTTPError as e:
                last_exc = e
                attempts += 1
                if attempts > self._max_retries:
                    break
                time.sleep(self._retry_backoff * (2 ** (attempts - 1)))
                continue
            if response.status_code >= 500 and attempts < self._max_retries:
                # Transient server errors are retryable; client errors aren't.
                attempts += 1
                time.sleep(self._retry_backoff * (2 ** (attempts - 1)))
                continue
            if response.status_code >= 400:
                try:
                    detail = response.json()
                except Exception:
                    detail = response.text
                raise AuthzServiceError(response.status_code, detail)
            if response.status_code == 204:
                return None
            return response.json()
        raise AuthzClientError(f"transport error after retries: {last_exc}")

    # ---- Cache helpers -------------------------------------------------------

    def _cache_get(self, key: tuple[str, str, str]) -> set[str] | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.expires_at <= time.monotonic():
            self._cache.pop(key, None)
            return None
        # LRU bookkeeping.
        self._cache.move_to_end(key)
        return set(entry.permissions)

    def _cache_put(self, key: tuple[str, str, str], permissions: set[str]) -> None:
        self._cache[key] = _CacheEntry(
            permissions=set(permissions),
            expires_at=time.monotonic() + self._cache_ttl,
        )
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_max_entries:
            self._cache.popitem(last=False)

    def cache_invalidate(
        self, *, tenant_id: str | None = None, application_id: str | None = None
    ) -> None:
        """Drop cached entries matching the given partition keys.

        Useful when admins update memberships and a long-running agent
        runtime needs its cached set refreshed.
        """
        keys = list(self._cache.keys())
        for k in keys:
            t, a, _ = k
            if (tenant_id is None or t == tenant_id) and (
                application_id is None or a == application_id
            ):
                self._cache.pop(k, None)

    # ---- API methods ---------------------------------------------------------

    def resolve_context(
        self,
        *,
        application_id: str,
        provider: str,
        issuer: str,
        subject: str,
        email: str | None = None,
        external_tenant_id: str | None = None,
        explicit_tenant_id: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> ResolvedContext:
        body = {
            "application_id": application_id,
            "provider": provider,
            "issuer": issuer,
            "subject": subject,
            "email": email,
            "external_tenant_id": external_tenant_id,
            "explicit_tenant_id": explicit_tenant_id,
            "claims": claims or {},
        }
        data = self._post("v1/resolve-context", body)
        return ResolvedContext(
            tenant_id=data["tenant_id"],
            application_id=data["application_id"],
            user_id=data["user_id"],
            roles=frozenset(data.get("roles") or ()),
            permissions=frozenset(data.get("permissions") or ()),
        )

    def authorize_decision(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None,
        delegation_token: str | None = None,
    ) -> AuthorizeResult:
        """Return the full structured ``/v1/authorize`` response.

        PEPs that need ``reason`` / ``required_permission`` for audit logs
        should call this; ``authorize`` and ``require`` remain bool-shaped
        wrappers on top of it for backwards-compatibility.
        """
        body = {
            "tenant_id": tenant_id,
            "application_id": application_id,
            "subject": subject.to_dict(),
            "resource": resource,
            "action": action,
            "context": context or {},
        }
        data = self._post("v1/authorize", body, _delegation_headers(delegation_token))
        return AuthorizeResult(
            allowed=bool(data.get("allowed")),
            decision=str(data.get("decision", "deny")),
            reason=str(data.get("reason", "")),
            required_permission=str(data.get("required_permission", f"{resource}.{action}")),
            matched_permissions=frozenset(data.get("matched_permissions") or ()),
        )

    def authorize(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None,
        delegation_token: str | None = None,
    ) -> bool:
        return self.authorize_decision(
            tenant_id=tenant_id,
            application_id=application_id,
            subject=subject,
            resource=resource,
            action=action,
            context=context,
            delegation_token=delegation_token,
        ).allowed

    def require(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None,
        delegation_token: str | None = None,
    ) -> None:
        result = self.authorize_decision(
            tenant_id=tenant_id,
            application_id=application_id,
            subject=subject,
            resource=resource,
            action=action,
            context=context,
            delegation_token=delegation_token,
        )
        if not result.allowed:
            raise PermissionDeniedError(result.required_permission)

    def bulk_authorize(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        checks: list[BulkCheck],
        context: dict[str, Any] | None = None,
        delegation_token: str | None = None,
    ) -> list[BulkCheckResult]:
        body = {
            "tenant_id": tenant_id,
            "application_id": application_id,
            "subject": subject.to_dict(),
            "checks": [{"resource": c.resource, "action": c.action} for c in checks],
            "context": context or {},
        }
        data = self._post("v1/bulk-authorize", body, _delegation_headers(delegation_token))
        return [
            BulkCheckResult(
                resource=r["resource"],
                action=r["action"],
                allowed=bool(r["allowed"]),
                reason=r["reason"],
            )
            for r in data.get("results", [])
        ]

    def get_effective_permissions(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        bypass_cache: bool = False,
        delegation_token: str | None = None,
    ) -> set[str]:
        # service_account_id must be in the key: two service accounts can
        # share the same (type, user_id, agent_id) tuple.
        cache_key = (
            tenant_id,
            application_id,
            f"{subject.type}:{subject.user_id}:{subject.agent_id}:{subject.service_account_id}"
            f":{subject.user_ref}:{subject.agent_name}"
            # A grant narrows the set, so it must partition the cache too.
            + (
                f":d={hashlib.sha256(delegation_token.encode()).hexdigest()[:24]}"
                if delegation_token
                else ""
            ),
        )
        if self._cache_ttl > 0 and not bypass_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached
        body = {
            "tenant_id": tenant_id,
            "application_id": application_id,
            "subject": subject.to_dict(),
        }
        data = self._post(
            "v1/effective-permissions", body, _delegation_headers(delegation_token)
        )
        permissions = set(data.get("permissions") or [])
        if self._cache_ttl > 0:
            self._cache_put(cache_key, permissions)
        return permissions

    # ---- Delegation grants ---------------------------------------------------

    def create_delegation(
        self,
        *,
        tenant_id: str,
        application_id: str,
        user_id: str | None = None,
        agent_id: str | None = None,
        permissions: list[str] | set[str] | None = None,
        ttl_seconds: int | None = None,
        purpose: str | None = None,
        user_ref: UserRef | None = None,
        agent_name: str | None = None,
    ) -> Delegation:
        """Issue a grant; hand ``result.token`` to the agent runtime.

        Give the user as ``user_id`` or ``user_ref`` and the agent as
        ``agent_id`` or ``agent_name``. ``permissions=None`` delegates
        everything the agent may currently do for this user. A subset
        outside ``user ∩ agent`` is rejected (403). An empty result (nothing
        delegable, or ``permissions=[]``) still issues a grant that binds the
        run and authorizes nothing.
        """
        body: dict[str, Any] = {"tenant_id": tenant_id, "application_id": application_id}
        if user_id is not None:
            body["user_id"] = user_id
        if user_ref is not None:
            body["user_ref"] = user_ref.to_dict()
        if agent_id is not None:
            body["agent_id"] = agent_id
        if agent_name is not None:
            body["agent_name"] = agent_name
        if permissions is not None:
            body["permissions"] = sorted(permissions)
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if purpose is not None:
            body["purpose"] = purpose
        return Delegation.from_dict(self._post("v1/delegations", body))

    def get_delegation(self, delegation_id: str) -> Delegation:
        return Delegation.from_dict(self._request("GET", f"v1/delegations/{delegation_id}"))

    def revoke_delegation(self, delegation_id: str) -> None:
        self._request("DELETE", f"v1/delegations/{delegation_id}")

    def revoke_delegations(
        self,
        *,
        tenant_id: str,
        user_id: str | None = None,
        agent_id: str | None = None,
        user_ref: UserRef | None = None,
        agent_name: str | None = None,
        application_id: str | None = None,
    ) -> int:
        """Kill switch: revoke every active grant of a tenant / user / agent.

        ``agent_name`` needs ``application_id``.
        """
        body: dict[str, Any] = {"tenant_id": tenant_id}
        if user_id:
            body["user_id"] = user_id
        if agent_id:
            body["agent_id"] = agent_id
        if user_ref is not None:
            body["user_ref"] = user_ref.to_dict()
        if agent_name is not None:
            body["agent_name"] = agent_name
        if application_id is not None:
            body["application_id"] = application_id
        return int(self._post("v1/delegations/revoke", body)["revoked"])

    def introspect_delegation(self, token: str) -> dict[str, Any]:
        """``{"active": bool, ...}`` — inactive results carry a ``reason``."""
        return dict(self._post("v1/delegations/introspect", {"token": token}))
