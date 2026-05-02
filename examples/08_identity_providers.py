"""Identity providers: normalizing claims from Entra, Cognito, GCP, generic OIDC.

The AuthZ system never branches on which IdP issued a token. Instead the
provider-specific claim shape is folded into an ``IdentityPrincipal`` at
the boundary, and everything downstream consumes that one type.

Demonstrates:
- The four built-in normalizers
- The minimum claims each one needs (subject, issuer, optional tenant id)
- ``normalize_principal`` as a single dispatch entry point

Run with::

    python examples/08_identity_providers.py
"""

from __future__ import annotations

from authzkit.identity import (
    normalize_cognito,
    normalize_entra,
    normalize_gcp,
    normalize_oidc,
)
from authzkit.identity.base import normalize_principal


def show(label: str, principal) -> None:
    print(f"{label}")
    print(f"  provider={principal.provider}")
    print(f"  issuer={principal.issuer}")
    print(f"  subject={principal.subject}")
    print(f"  email={principal.email}")
    print(f"  external_tenant_id={principal.external_tenant_id}")
    print()


def main() -> None:
    entra = normalize_entra({
        "iss": "https://login.microsoftonline.com/<tenant-id>/v2.0",
        "oid": "8e7d-...-alice",
        "tid": "<tenant-id>",
        "preferred_username": "alice@acme.com",
    })
    show("Azure Entra (oid > sub, tid -> external_tenant_id)", entra)

    cognito = normalize_cognito({
        "iss": "https://cognito-idp.eu-central-1.amazonaws.com/<pool>",
        "sub": "9f87-...-bob",
        "email": "bob@acme.com",
        "custom:tenant_id": "acme",
    })
    show("AWS Cognito (custom:tenant_id -> external_tenant_id)", cognito)

    gcp = normalize_gcp({
        "iss": "https://accounts.google.com",
        "sub": "1023-...-carol",
        "email": "carol@acme.com",
        "firebase": {"tenant": "tenant-acme"},
    })
    show("GCP Identity (firebase.tenant / tenant / organization_id)", gcp)

    oidc = normalize_oidc({
        "iss": "https://idp.example.com",
        "sub": "user-42",
        "email": "dave@acme.com",
        "organization_id": "org_acme",
    })
    show("Generic OIDC (organization_id/tenant_id/tid)", oidc)

    # Single-call dispatcher — handy when the provider id is data, not code.
    via_dispatcher = normalize_principal(
        "azure_entra",
        {
            "iss": "https://login.microsoftonline.com/<tenant>/v2.0",
            "oid": "abc",
            "tid": "tenantX",
        },
    )
    print(f"normalize_principal('azure_entra', ...) -> {via_dispatcher.provider}/{via_dispatcher.subject}")


if __name__ == "__main__":
    main()
