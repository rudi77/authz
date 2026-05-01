"""Generic OIDC claim normalization."""

from __future__ import annotations

from typing import Any, Mapping

from authzkit.identity.base import PROVIDER_GENERIC_OIDC, IdentityPrincipal


def normalize_oidc(claims: Mapping[str, Any]) -> IdentityPrincipal:
    """Normalize standard OIDC ID token claims."""
    subject = claims.get("sub")
    issuer = claims.get("iss")
    if not subject or not issuer:
        raise ValueError("OIDC claims missing sub/iss")
    return IdentityPrincipal(
        provider=PROVIDER_GENERIC_OIDC,
        issuer=str(issuer),
        subject=str(subject),
        email=claims.get("email"),
        external_tenant_id=(
            claims.get("tenant_id") or claims.get("tid") or claims.get("organization_id")
        ),
        claims=dict(claims),
    )
