"""Azure Entra ID claim normalization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from authzkit.identity.base import PROVIDER_AZURE_ENTRA, IdentityPrincipal


def normalize_entra(claims: Mapping[str, Any]) -> IdentityPrincipal:
    """Normalize Azure Entra ID claims.

    Subject precedence: ``oid`` (object id, stable across renames) > ``sub``.
    Tenant id comes from the ``tid`` claim. Email falls back through
    ``preferred_username`` because Entra often omits ``email`` for guest users.
    """
    subject = claims.get("oid") or claims.get("sub")
    if not subject:
        raise ValueError("Azure Entra claims missing oid/sub")
    issuer = claims.get("iss")
    if not issuer:
        raise ValueError("Azure Entra claims missing iss")
    return IdentityPrincipal(
        provider=PROVIDER_AZURE_ENTRA,
        issuer=str(issuer),
        subject=str(subject),
        email=claims.get("email") or claims.get("preferred_username"),
        external_tenant_id=claims.get("tid"),
        claims=dict(claims),
    )
