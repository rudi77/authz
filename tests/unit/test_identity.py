"""Identity claim normalization tests."""

import pytest

from authzkit.identity import (
    normalize_cognito,
    normalize_entra,
    normalize_gcp,
    normalize_oidc,
    normalize_principal,
)


def test_entra_uses_oid_over_sub():
    claims = {
        "iss": "https://login.microsoftonline.com/abc/v2.0",
        "oid": "object-id-123",
        "sub": "subject-id-999",
        "tid": "tenant-id",
        "preferred_username": "alice@contoso.com",
    }
    p = normalize_entra(claims)
    assert p.subject == "object-id-123"
    assert p.email == "alice@contoso.com"
    assert p.external_tenant_id == "tenant-id"


def test_entra_falls_back_to_sub():
    claims = {"iss": "https://x", "sub": "s1"}
    p = normalize_entra(claims)
    assert p.subject == "s1"


def test_entra_missing_subject_raises():
    with pytest.raises(ValueError):
        normalize_entra({"iss": "https://x"})


def test_cognito_custom_tenant_attribute():
    claims = {
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/pool",
        "sub": "user-123",
        "email": "a@b.com",
        "custom:tenant_id": "tenant-xyz",
    }
    p = normalize_cognito(claims)
    assert p.external_tenant_id == "tenant-xyz"


def test_gcp_firebase_tenant():
    claims = {
        "iss": "https://securetoken.google.com/proj",
        "sub": "uid",
        "firebase": {"tenant": "t-1"},
    }
    p = normalize_gcp(claims)
    assert p.external_tenant_id == "t-1"


def test_oidc_generic():
    claims = {"iss": "https://idp", "sub": "u-1", "tenant_id": "t1"}
    p = normalize_oidc(claims)
    assert p.subject == "u-1"
    assert p.external_tenant_id == "t1"


def test_normalize_principal_dispatch():
    p = normalize_principal(
        "azure_entra",
        {"iss": "https://x", "oid": "o1", "tid": "t1"},
    )
    assert p.provider == "azure_entra"
    assert p.subject == "o1"
