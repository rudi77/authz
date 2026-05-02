"""IdentityPrincipal — normalized identity from external providers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IdentityPrincipal:
    """Normalized result from OIDC/JWT claims.

    The IdentityPrincipal is the boundary between external Identity Providers
    and the AuthZ system. Provider-specific claim shapes are folded into this
    canonical form so the rest of the system never branches on provider.
    """

    provider: str
    issuer: str
    subject: str
    email: str | None = None
    external_tenant_id: str | None = None
    claims: Mapping[str, Any] = field(default_factory=dict)


PROVIDER_AZURE_ENTRA = "azure_entra"
PROVIDER_AWS_COGNITO = "aws_cognito"
PROVIDER_GCP_IDENTITY = "gcp_identity"
PROVIDER_GENERIC_OIDC = "generic_oidc"


def normalize_principal(provider: str, claims: Mapping[str, Any]) -> IdentityPrincipal:
    """Normalize claims from a provider into an IdentityPrincipal."""
    # Imports kept local to avoid a circular dependency at module import time.
    from authzkit.identity.aws_cognito import normalize_cognito
    from authzkit.identity.azure_entra import normalize_entra
    from authzkit.identity.gcp_identity import normalize_gcp
    from authzkit.identity.generic_oidc import normalize_oidc

    normalizers = {
        PROVIDER_AZURE_ENTRA: normalize_entra,
        PROVIDER_AWS_COGNITO: normalize_cognito,
        PROVIDER_GCP_IDENTITY: normalize_gcp,
        PROVIDER_GENERIC_OIDC: normalize_oidc,
    }
    fn = normalizers.get(provider, normalize_oidc)
    return fn(claims)
