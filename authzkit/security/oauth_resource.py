"""OAuth 2.0 Resource-Server JWT resolution.

Wraps the existing :class:`authzkit.identity.jwt_validation.JWTValidator`
with a config layer that maps external IdP claim shapes onto the internal
``admin`` / ``runtime`` / ``tenant:<id>`` scope vocabulary, and pulls the
tenant id from a configurable claim.

The resolver is a thin layer because the heavy lifting (JWKS discovery,
caching, signature + iss/aud/exp checks) already lives in
``authzkit.identity``.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from authzkit.identity.jwt_validation import (
    JWTValidationError,
    JWTValidator,
    JWTValidatorConfig,
)
from authzkit.security.api_keys import SCOPE_ADMIN, SCOPE_RUNTIME
from authzkit.security.principal import TokenPrincipal

_log = logging.getLogger("authz.oauth_resource")

# ``tenant:<uuid|slug>`` — same shape ApiKey scopes carry; we keep the regex
# permissive on the id part so existing keys-style scopes interoperate.
_TENANT_SCOPE_RE = re.compile(r"^tenant:[A-Za-z0-9_\-:]+$")
_INTERNAL_SURFACE_SCOPES = frozenset({SCOPE_ADMIN, SCOPE_RUNTIME})


@dataclass(frozen=True)
class IssuerConfig:
    """Per-issuer rules for translating a verified JWT into a ``TokenPrincipal``.

    Defaults assume a generic OIDC issuer with a standard ``scope`` claim.
    Override per IdP — Entra uses ``scp``, Okta uses ``scope`` or ``groups``,
    Cognito puts custom data under ``custom:...``.
    """

    issuer: str
    audience: str | tuple[str, ...]
    jwks_url: str | None = None
    algorithms: tuple[str, ...] = ("RS256",)
    leeway_seconds: int = 30
    scope_claim: str = "scope"
    # ``" "`` for the OIDC default. ``None`` means the claim is already a list.
    scope_separator: str | None = " "
    # Mapping from external scope (e.g. ``"AuthZ.Admin"``) to internal
    # (``"admin"``). Unmapped entries pass through unchanged — useful for
    # IdPs that already emit ``"admin"`` / ``"runtime"`` directly.
    scope_map: Mapping[str, str] = field(default_factory=dict)
    tenant_claim: str | None = "tid"
    # Optional prefix prepended to the raw claim value to namespace external
    # tenant ids. Mostly useful when several IdPs share one authz instance.
    tenant_prefix: str = ""

    def audiences(self) -> tuple[str, ...]:
        if isinstance(self.audience, str):
            return (self.audience,)
        return tuple(self.audience)


class JwtResolver:
    """Validate JWTs and map their claims onto :class:`TokenPrincipal`."""

    def __init__(
        self,
        issuers: list[IssuerConfig],
        *,
        validator: JWTValidator | None = None,
        jwks_ttl_seconds: float = 600.0,
        self_issuer: str | None = None,
        self_jwks_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        # Detect a configuration collision where the AS self-issuer URL
        # also appears in the operator's external-issuer list. The
        # external config would be silently dropped (and replaced by an
        # auto-injected self config with different scope_claim /
        # tenant_claim), so we surface it loudly. Operators who genuinely
        # want both should distinguish them by URL.
        if self_issuer is not None:
            collisions = [
                cfg for cfg in issuers if cfg.issuer == self_issuer and cfg is not None
            ]
            external_collisions = [
                cfg
                for cfg in collisions
                if cfg.scope_claim != "scope"
                or cfg.tenant_claim != "tenant_id"
                or cfg.scope_map
            ]
            if external_collisions:
                raise ValueError(
                    f"self-issuer {self_issuer!r} collides with an external "
                    "issuer config that has custom scope_claim/tenant_claim/scope_map. "
                    "Self-issued tokens bypass that config; either remove the duplicate "
                    "entry from AUTHZ_OAUTH_RESOURCE_ISSUERS or give the AS a distinct "
                    "AUTHZ_OAUTH_ISSUER URL."
                )
        self._configs: dict[str, IssuerConfig] = {cfg.issuer: cfg for cfg in issuers}
        self._self_issuer = self_issuer
        self._self_jwks_provider = self_jwks_provider
        # Convert IssuerConfig → JWTValidatorConfig once; pyjwt only needs
        # iss/aud/jwks_url/algorithms/leeway. Re-use the existing validator
        # so JWKS caching is shared across requests. The self-issuer is
        # excluded from the external validator entirely so we don't try to
        # discover an OIDC endpoint against ourselves.
        external_configs = [cfg for cfg in issuers if cfg.issuer != self_issuer]
        validator_configs = [
            JWTValidatorConfig(
                issuer=cfg.issuer,
                # Pass the full audience tuple/string through so PyJWT can
                # accept any of the configured audiences. Previously we
                # forwarded only ``audiences()[0]``, silently rejecting
                # tokens that carried the second-or-later audience.
                audience=cfg.audience,
                jwks_url=cfg.jwks_url,
                algorithms=cfg.algorithms,
                leeway_seconds=cfg.leeway_seconds,
            )
            for cfg in external_configs
        ]
        self._validator = validator or JWTValidator(
            validator_configs, jwks_ttl_seconds=jwks_ttl_seconds
        )

    @property
    def issuers(self) -> tuple[str, ...]:
        return tuple(self._configs)

    def resolve(self, token: str) -> TokenPrincipal:
        """Validate the token and project its claims into a TokenPrincipal.

        Raises :class:`JWTValidationError` for any failure — signature,
        unknown issuer, audience mismatch, or expiry. Callers translate
        that into a RFC 6750 ``invalid_token`` 401.
        """
        # Peek at the iss claim to route to the right issuer config; the
        # underlying JWTValidator does the same check during verification.
        issuer = _peek_issuer(token)
        config = self._configs.get(issuer or "")
        if config is None:
            raise JWTValidationError(f"unknown issuer: {issuer}")
        if self._self_issuer is not None and issuer == self._self_issuer:
            claims = self._validate_self_issued(token, config)
        else:
            claims = self._validator.validate(token, expected_issuer=config.issuer)
        # PyJWT enforces audience for the tuple case directly (any-match
        # semantics); no extra check needed here.
        scopes = _map_scopes(claims, config)
        tenant_id = _extract_tenant(claims, config)
        if tenant_id is not None and not scopes:
            # Tenant-bound caller with no other scope → implicit tenant scope,
            # matching the API-key "tenant-only key" behaviour.
            scopes = (f"tenant:{tenant_id}",)
        client_id = claims.get("client_id") or claims.get("azp")
        subject = claims.get("sub") or ""
        return TokenPrincipal(
            issuer=config.issuer,
            subject=subject,
            client_id=client_id,
            scopes=scopes,
            tenant_id=tenant_id,
            claims=claims,
        )

    def _validate_self_issued(
        self, token: str, config: IssuerConfig
    ) -> dict[str, Any]:
        """Verify a token whose issuer is this service itself.

        Bypasses HTTP entirely — we read the active/retiring public JWKs
        directly from the local :class:`SigningKeyService`. This makes the
        self-trust loop deterministic in single-instance deployments and
        keeps tests offline.
        """
        if self._self_jwks_provider is None:  # pragma: no cover - defensive
            raise JWTValidationError("self-issuer configured without JWKS provider")
        import jwt

        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise JWTValidationError(f"malformed token: {exc}") from exc
        kid = header.get("kid")
        jwks = self._self_jwks_provider()
        key_jwk = next(
            (k for k in jwks.get("keys", []) if k.get("kid") == kid), None
        )
        if key_jwk is None:
            raise JWTValidationError(f"no self-issued key matches kid={kid}")
        public_key = jwt.PyJWK(key_jwk).key
        audiences = list(config.audiences()) if config.audiences() else None
        try:
            return jwt.decode(
                token,
                key=public_key,
                algorithms=list(config.algorithms),
                audience=audiences,
                issuer=config.issuer,
                options={"verify_aud": bool(audiences)},
                leeway=config.leeway_seconds,
            )
        except jwt.PyJWTError as exc:
            raise JWTValidationError(f"invalid self-issued token: {exc}") from exc


def _peek_issuer(token: str) -> str | None:
    """Read the ``iss`` claim without verifying the signature.

    Safe because the actual signature check happens against the issuer's
    JWKS afterward — a forged iss can't survive that step.
    """
    import jwt

    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
    except Exception as exc:  # malformed token bytes
        raise JWTValidationError(f"malformed token: {exc}") from exc
    iss = payload.get("iss")
    return str(iss) if iss else None


def _map_scopes(claims: Mapping[str, Any], config: IssuerConfig) -> tuple[str, ...]:
    """Project the configured scope claim onto the internal vocabulary.

    Steps: read raw claim → tokenize → per-token map via ``scope_map`` →
    keep only internal surface scopes (``admin``/``runtime``) or
    ``tenant:<id>`` forms. Anything else is silently dropped because
    handing a token a recognised-but-unknown scope would otherwise leak
    capability through to the engine.
    """
    raw = claims.get(config.scope_claim)
    if raw is None:
        return ()
    tokens: Iterable[str]
    if isinstance(raw, str):
        tokens = (
            [raw] if config.scope_separator is None else raw.split(config.scope_separator)
        )
    elif isinstance(raw, list):
        tokens = [str(t) for t in raw]
    else:
        tokens = [str(raw)]
    mapped: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        mapped_value = config.scope_map.get(token, token)
        if mapped_value in seen:
            continue
        if mapped_value in _INTERNAL_SURFACE_SCOPES or _TENANT_SCOPE_RE.match(
            mapped_value
        ):
            mapped.append(mapped_value)
            seen.add(mapped_value)
        elif token in config.scope_map:
            # Operator explicitly mapped this external scope but the target
            # isn't in the internal vocabulary — that's almost certainly a
            # misconfiguration. Log loudly so it shows up in startup
            # smoke-tests rather than as a silent capability loss.
            _log.warning(
                "issuer %r scope_map[%r]=%r is not a recognised internal "
                "scope (admin / runtime / tenant:<id>); dropping",
                config.issuer,
                token,
                mapped_value,
            )
    return tuple(mapped)


def _extract_tenant(claims: Mapping[str, Any], config: IssuerConfig) -> str | None:
    """Pull the tenant id from a configurable claim with optional prefix.

    Only string and integer claim values are accepted. Lists, dicts, and
    other shapes (e.g. an IdP that mistakenly emits an array of tenant
    ids) are treated as misconfiguration and rejected — silently
    stringifying them would mint nonsensical tenant ids that don't
    correspond to any real tenant row.
    """
    if config.tenant_claim is None:
        return None
    value = claims.get(config.tenant_claim)
    if value is None:
        return None
    if not isinstance(value, str | int):
        _log.warning(
            "issuer %r tenant_claim %r value has unexpected type %s; ignoring",
            config.issuer,
            config.tenant_claim,
            type(value).__name__,
        )
        return None
    return f"{config.tenant_prefix}{value}"
