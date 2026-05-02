"""Google Identity Platform claim normalization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from authzkit.identity.base import PROVIDER_GCP_IDENTITY, IdentityPrincipal


def normalize_gcp(claims: Mapping[str, Any]) -> IdentityPrincipal:
    """Normalize Google Identity Platform / Firebase Auth claims."""
    subject = claims.get("sub") or claims.get("user_id")
    issuer = claims.get("iss")
    if not subject or not issuer:
        raise ValueError("GCP Identity claims missing sub/iss")
    external_tenant = (
        claims.get("firebase", {}).get("tenant")
        if isinstance(claims.get("firebase"), Mapping)
        else None
    )
    external_tenant = external_tenant or claims.get("tenant") or claims.get("organization_id")
    return IdentityPrincipal(
        provider=PROVIDER_GCP_IDENTITY,
        issuer=str(issuer),
        subject=str(subject),
        email=claims.get("email"),
        external_tenant_id=external_tenant,
        claims=dict(claims),
    )
