"""Identity normalization for OIDC/JWT claims from various providers."""

from authzkit.identity.aws_cognito import normalize_cognito
from authzkit.identity.azure_entra import normalize_entra
from authzkit.identity.base import IdentityPrincipal, normalize_principal
from authzkit.identity.gcp_identity import normalize_gcp
from authzkit.identity.generic_oidc import normalize_oidc

__all__ = [
    "IdentityPrincipal",
    "normalize_cognito",
    "normalize_entra",
    "normalize_gcp",
    "normalize_oidc",
    "normalize_principal",
]


def __getattr__(name):
    # Lazy-load JWT validator so the optional pyjwt dep stays optional.
    if name in ("JWTValidator", "JWTValidatorConfig", "JWTValidationError"):
        from authzkit.identity import jwt_validation as _jv

        return getattr(_jv, name)
    raise AttributeError(name)
