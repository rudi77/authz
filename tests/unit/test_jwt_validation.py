"""Hardening tests for the JWKS / OIDC discovery code path.

Tests the static decode helper directly so they don't require PyJWT to be
installed (the full :class:`JWTValidator` constructor pulls in PyJWT lazily).
The JSON-decode guard is the main correctness fix being verified.
"""

from __future__ import annotations

import httpx
import pytest

from authzkit.identity.jwt_validation import JWTValidationError, JWTValidator, _decode_json


def _pyjwt_usable() -> bool:
    """Returns True only if PyJWT (and its cryptography stack) actually loads.

    ``pytest.importorskip('jwt')`` is not enough because some environments
    have PyJWT on disk but the cryptography native bindings are broken,
    raising PanicException rather than ImportError on import.
    """
    try:
        import jwt  # noqa: F401
    except BaseException:  # noqa: BLE001 — PanicException isn't an Exception
        return False
    return True


_pyjwt_required = pytest.mark.skipif(
    not _pyjwt_usable(),
    reason="PyJWT (or its cryptography backend) is not importable in this env",
)


def _resp(content: bytes, content_type: str = "application/json") -> httpx.Response:
    return httpx.Response(200, content=content, headers={"content-type": content_type})


def test_decode_json_passes_through_object():
    assert _decode_json(_resp(b'{"foo":"bar"}'), "x") == {"foo": "bar"}


def test_decode_json_raises_on_html_body():
    response = _resp(b"<html>not json</html>", content_type="text/html")
    with pytest.raises(JWTValidationError, match="non-JSON"):
        _decode_json(response, "JWKS endpoint")


def test_decode_json_raises_on_empty_body():
    with pytest.raises(JWTValidationError, match="non-JSON"):
        _decode_json(_resp(b""), "OIDC discovery")


def test_decode_json_raises_on_truncated_body():
    with pytest.raises(JWTValidationError, match="non-JSON"):
        _decode_json(_resp(b'{"keys":'), "JWKS endpoint")


@_pyjwt_required
def test_resolve_jwks_url_rejects_non_object_discovery_payload():
    """OIDC discovery payload that is JSON but not an object (e.g. a list)
    must be rejected — otherwise ``.get('jwks_uri')`` raises AttributeError
    instead of a clean JWTValidationError."""
    from authzkit.identity.jwt_validation import JWTValidatorConfig

    class _StubTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b'["a","b"]',
                headers={"content-type": "application/json"},
            )

    config = JWTValidatorConfig(issuer="https://idp.example")
    validator = JWTValidator(
        [config],
        http_client=httpx.Client(transport=_StubTransport()),
    )
    with pytest.raises(JWTValidationError, match="non-object"):
        validator._resolve_jwks_url(config)


@_pyjwt_required
def test_get_jwks_rejects_non_object_payload():
    from authzkit.identity.jwt_validation import JWTValidatorConfig

    class _StubTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b'"oops just a string"',
                headers={"content-type": "application/json"},
            )

    config = JWTValidatorConfig(
        issuer="https://idp.example",
        jwks_url="https://idp.example/jwks",
    )
    validator = JWTValidator(
        [config],
        http_client=httpx.Client(transport=_StubTransport()),
    )
    with pytest.raises(JWTValidationError, match="non-object"):
        validator._get_jwks(config)
