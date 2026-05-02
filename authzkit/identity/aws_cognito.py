"""AWS Cognito claim normalization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from authzkit.identity.base import PROVIDER_AWS_COGNITO, IdentityPrincipal


def normalize_cognito(claims: Mapping[str, Any]) -> IdentityPrincipal:
    """Normalize AWS Cognito User Pool claims.

    Cognito carries application tenant ids only via custom attributes (the
    ``custom:tenant_id`` convention). User pool id is encoded in the issuer URL.
    """
    subject = claims.get("sub")
    issuer = claims.get("iss")
    if not subject or not issuer:
        raise ValueError("Cognito claims missing sub/iss")
    return IdentityPrincipal(
        provider=PROVIDER_AWS_COGNITO,
        issuer=str(issuer),
        subject=str(subject),
        email=claims.get("email"),
        external_tenant_id=(
            claims.get("custom:tenant_id")
            or claims.get("custom:tenantId")
            or claims.get("tenant_id")
        ),
        claims=dict(claims),
    )
