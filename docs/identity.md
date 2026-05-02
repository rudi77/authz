# Identity & JWT

The authz platform never authenticates users itself. Your application
validates the IdP's token, normalizes the verified claims into an
`IdentityPrincipal`, and hands that to the PDP. This page walks the
boundary in detail.

## The IdentityPrincipal

A frozen dataclass with five fields:

```python
IdentityPrincipal(
    provider="azure_entra",
    issuer="https://login.microsoftonline.com/<tenant>/v2.0",
    subject="<oid>",
    email="alice@acme.com",            # optional
    external_tenant_id="<tenant>",     # optional, for tenant routing
    claims={...},                      # original claims, for ABAC context
)
```

`(provider, issuer, subject)` is the identity primary key. Two principals
with the same triple are the same person. Email is informational; never
use it as the user identifier (people change them, IdPs reissue them).

## Built-in normalizers

| Provider | Function | Subject source | External tenant source |
|----------|----------|----------------|------------------------|
| Azure Entra | `normalize_entra` | `oid` (preferred) → `sub` | `tid` |
| AWS Cognito | `normalize_cognito` | `sub` | `custom:tenant_id` / `custom:tenantId` / `tenant_id` |
| GCP Identity | `normalize_gcp` | `sub` → `user_id` | `firebase.tenant` / `tenant` / `organization_id` |
| Generic OIDC | `normalize_oidc` | `sub` | `tenant_id` / `tid` / `organization_id` |

```python
from authzkit.identity import normalize_entra, normalize_principal

# Direct
principal = normalize_entra(verified_claims)

# Or via the dispatcher (when provider id is data, not code)
principal = normalize_principal("azure_entra", verified_claims)
```

Adding a custom provider is a one-function exercise: write something
that takes `claims` and returns an `IdentityPrincipal`.

## JWT validation

The optional `JWTValidator` handles signature verification and claim
checks against an IdP's JWKS. It's only for the application side — the
PDP never sees the raw token.

```python
from authzkit.identity import JWTValidator, JWTValidatorConfig

validator = JWTValidator(configs=[
    JWTValidatorConfig(
        issuer="https://login.microsoftonline.com/<tenant_id>/v2.0",
        audience="api://<your-app-id>",
    ),
    JWTValidatorConfig(
        issuer="https://cognito-idp.<region>.amazonaws.com/<pool>",
        audience="<cognito-client-id>",
    ),
])

principal = validator.validate_to_principal(
    bearer_token, provider="azure_entra"
)
```

`JWTValidator`:

- Discovers `jwks_uri` via OIDC discovery if not provided
- Caches the JWKS for `jwks_ttl_seconds` (default 600)
- Verifies signature, issuer, audience, expiry, with configurable
  leeway for clock drift
- Re-fetches the JWKS once if the kid isn't in the cached set
  (covers normal key rotation)

Requires `pyjwt[crypto]`. The base library doesn't pull it in so the
service container stays lean.

### Failure modes

| Symptom | Likely cause |
|---------|--------------|
| `unknown issuer` | The token's `iss` doesn't match any configured issuer. Check the trailing `/v2.0` for Entra. |
| `JWKS fetch failed` | The IdP is unreachable or the discovery URL is wrong. |
| `no JWKS key matches kid` | Keys rotated faster than the cache TTL. Lower the TTL or accept the one re-fetch. |
| `invalid token` | Signature, expiry, audience, or issuer claim mismatch. Inspect with `jwt.decode(token, options={"verify_signature": False})`. |

## Tenant resolution

After you have an `IdentityPrincipal`, the PDP needs to map it to an
internal tenant. Three resolution paths, in order:

1. **Explicit tenant_id**. If the caller passes one to
   `resolve_context`, the PDP trusts it (still subject to membership
   check).
2. **External tenant mapping**. The PDP looks up
   `(provider, issuer, external_tenant_id)` in the
   `tenant_identity_mappings` table. Set this up with
   `POST /v1/tenants/{id}/mappings` or the admin SDK's
   `map_tenant_external`.
3. **Single-tenant inference**. If the user already has exactly one
   active membership, that tenant wins.

If none resolves, the PDP returns `no_active_membership` (the principal
is anonymous as far as the PDP knows).

## Auto-provisioning

`resolve-context` will create the *user* row on first sight when
`AUTHZ_AUTO_PROVISION_USER=true` (the default). This is safe because
the user record is dormant until paired with a membership.

It will **not** create the tenant unless you flip
`AUTHZ_AUTO_PROVISION_TENANT=true` — that's a business decision (does
the IdP know about all your tenants? do you want self-service?).

It will **never** create memberships. Memberships are how access is
granted, so they require an explicit admin action: invitation,
SCIM provision, manual API call.

## See also

- [Identity providers example](../examples/08_identity_providers.py) —
  shows all four normalizers
- [JWT recipe](../examples/jwt_resolve_recipe.py) — full
  validate-then-authorize flow
