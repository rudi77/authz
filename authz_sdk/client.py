"""HTTP client for the AuthZ Service.

Provides a synchronous interface backed by httpx. Includes a small bounded
LRU cache for ``effective_permissions`` because that's the hot path for
agent runs (spec section 14).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

import httpx

from authzkit.exceptions import PermissionDeniedError


class AuthzClientError(Exception):
    """Base error for SDK-level problems (transport, validation)."""


class AuthzServiceError(AuthzClientError):
    """Raised when the AuthZ service returns a non-success status code."""

    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"AuthZ service returned {status_code}: {body}")


@dataclass(frozen=True)
class Subject:
    type: str  # "user" | "agent"
    user_id: str | None = None
    agent_id: str | None = None
    service_account_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type}
        if self.user_id is not None:
            out["user_id"] = self.user_id
        if self.agent_id is not None:
            out["agent_id"] = self.agent_id
        if self.service_account_id is not None:
            out["service_account_id"] = self.service_account_id
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
class ResolvedContext:
    tenant_id: str
    application_id: str
    user_id: str
    roles: frozenset[str]
    permissions: frozenset[str]


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

    def _post(self, path: str, body: dict) -> dict:
        attempts = 0
        last_exc: Exception | None = None
        while attempts <= self._max_retries:
            try:
                response = self._http.post(path, json=body)
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

    def authorize(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        body = {
            "tenant_id": tenant_id,
            "application_id": application_id,
            "subject": subject.to_dict(),
            "resource": resource,
            "action": action,
            "context": context or {},
        }
        data = self._post("v1/authorize", body)
        return bool(data.get("allowed"))

    def require(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        if not self.authorize(
            tenant_id=tenant_id,
            application_id=application_id,
            subject=subject,
            resource=resource,
            action=action,
            context=context,
        ):
            raise PermissionDeniedError(f"{resource}.{action}")

    def bulk_authorize(
        self,
        *,
        tenant_id: str,
        application_id: str,
        subject: Subject,
        checks: list[BulkCheck],
        context: dict[str, Any] | None = None,
    ) -> list[BulkCheckResult]:
        body = {
            "tenant_id": tenant_id,
            "application_id": application_id,
            "subject": subject.to_dict(),
            "checks": [{"resource": c.resource, "action": c.action} for c in checks],
            "context": context or {},
        }
        data = self._post("v1/bulk-authorize", body)
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
    ) -> set[str]:
        cache_key = (
            tenant_id,
            application_id,
            f"{subject.type}:{subject.user_id}:{subject.agent_id}",
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
        data = self._post("v1/effective-permissions", body)
        permissions = set(data.get("permissions") or [])
        if self._cache_ttl > 0:
            self._cache_put(cache_key, permissions)
        return permissions
