"""Optional JWT validation helpers.

The AuthZ service intentionally **does not** validate user tokens — that is
the application's job (see spec §2.1). These helpers exist for the
application side: they verify a JWT against the issuer's JWKS, then turn
the verified claims into an :class:`IdentityPrincipal`.

Pulls in PyJWT only when this module is imported. Keep the dependency
optional so the AuthZ service container doesn't carry it unless needed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urljoin

import httpx

from authzkit.identity.base import IdentityPrincipal, normalize_principal


class JWTValidationError(Exception):
    """Raised when a JWT fails signature, claim, or freshness checks."""


@dataclass(frozen=True)
class JWTValidatorConfig:
    """Per-issuer validation rules.

    ``issuer`` and ``audience`` follow OIDC; ``jwks_url`` is auto-discovered
    via ``{issuer}/.well-known/openid-configuration`` when not provided.
    ``leeway_seconds`` covers small clock drift between this host and the IdP.
    """

    issuer: str
    audience: str | None = None
    jwks_url: str | None = None
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    leeway_seconds: int = 30


class JWTValidator:
    """Validates JWTs by fetching and caching the IdP's JWKS.

    Stateful by design: we cache JWKS keyed by issuer for ``jwks_ttl_seconds``
    so each request doesn't hit the IdP. The cache is per-instance so tests
    and multi-IdP deployments don't share state unexpectedly.
    """

    def __init__(
        self,
        configs: list[JWTValidatorConfig],
        *,
        jwks_ttl_seconds: float = 600.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        try:
            import jwt  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "JWTValidator requires PyJWT. Install with: pip install pyjwt[crypto]"
            ) from e
        self._configs = {c.issuer: c for c in configs}
        self._http = http_client or httpx.Client(timeout=5.0)
        self._jwks_ttl = jwks_ttl_seconds
        self._jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}

    def _resolve_jwks_url(self, config: JWTValidatorConfig) -> str:
        if config.jwks_url:
            return config.jwks_url
        # OIDC discovery: GET {issuer}/.well-known/openid-configuration
        # then read jwks_uri from the response.
        discovery_url = urljoin(
            config.issuer.rstrip("/") + "/", ".well-known/openid-configuration"
        )
        response = self._http.get(discovery_url)
        if response.status_code >= 400:
            raise JWTValidationError(
                f"OIDC discovery failed for {config.issuer}: {response.status_code}"
            )
        jwks_uri = response.json().get("jwks_uri")
        if not jwks_uri:
            raise JWTValidationError(
                f"OIDC discovery for {config.issuer} returned no jwks_uri"
            )
        return jwks_uri

    def _get_jwks(self, config: JWTValidatorConfig) -> dict[str, Any]:
        cached = self._jwks_cache.get(config.issuer)
        now = time.monotonic()
        if cached is not None and cached[1] > now:
            return cached[0]
        url = self._resolve_jwks_url(config)
        response = self._http.get(url)
        if response.status_code >= 400:
            raise JWTValidationError(f"JWKS fetch failed: {response.status_code}")
        jwks = response.json()
        self._jwks_cache[config.issuer] = (jwks, now + self._jwks_ttl)
        return jwks

    def validate(self, token: str, *, expected_issuer: str | None = None) -> dict[str, Any]:
        """Verify signature + claims and return the decoded payload."""
        import jwt
        from jwt import PyJWKClient

        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid")

        # Determine which configured issuer this token is for. If the caller
        # specified one we trust their hint; otherwise read iss from the
        # unverified payload — this is safe because we still verify the
        # signature against the issuer's JWKS afterward.
        if expected_issuer is None:
            unverified_claims = jwt.decode(
                token, options={"verify_signature": False, "verify_aud": False}
            )
            expected_issuer = unverified_claims.get("iss")
        config = self._configs.get(expected_issuer or "")
        if config is None:
            raise JWTValidationError(f"unknown issuer: {expected_issuer}")

        jwks = self._get_jwks(config)
        key = next(
            (k for k in jwks.get("keys", []) if k.get("kid") == kid),
            None,
        )
        if key is None:
            # Refresh JWKS once in case keys rotated between cache fetches.
            self._jwks_cache.pop(config.issuer, None)
            jwks = self._get_jwks(config)
            key = next(
                (k for k in jwks.get("keys", []) if k.get("kid") == kid), None
            )
        if key is None:
            raise JWTValidationError(f"no JWKS key matches kid={kid}")

        public_key = PyJWKClient._jwk_set_to_key(jwks, kid)  # type: ignore[attr-defined]

        options = {"verify_aud": config.audience is not None}
        try:
            return jwt.decode(
                token,
                key=public_key,
                algorithms=list(config.algorithms),
                audience=config.audience,
                issuer=config.issuer,
                options=options,
                leeway=config.leeway_seconds,
            )
        except jwt.PyJWTError as e:
            raise JWTValidationError(f"invalid token: {e}") from e

    def validate_to_principal(
        self,
        token: str,
        *,
        provider: str,
        expected_issuer: str | None = None,
    ) -> IdentityPrincipal:
        """Verify a JWT then normalize its claims into an IdentityPrincipal."""
        claims = self.validate(token, expected_issuer=expected_issuer)
        return normalize_principal(provider, claims)
