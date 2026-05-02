# API Keys

How service-to-service auth works, and how to operate it without
locking yourself out.

## Two key sources

The service checks API keys against two sources, in order:

1. **Bootstrap env keys** (`AUTHZ_API_KEYS`) — comma-separated, all
   implicitly admin-scoped. Suitable for first deploys, CI, and dev.
2. **Database keys** (`api_keys` table) — hashed, scoped, rotatable.
   Suitable for everything past the first deploy.

DB lookup wins when both succeed. Once any active DB-backed key
exists, the service is in **locked-down mode** — every request must
present a key that matches one of the two sources.

When neither source has any keys, the service starts in **dev mode**
and accepts every caller. A `WARNING` is logged at startup. The first
DB-backed key you create flips out of dev mode automatically; there is
no flag to toggle.

## Scopes

A DB-backed key carries one or more scopes:

| Scope | Grants |
|-------|--------|
| `admin` | Full read/write on management endpoints + runtime endpoints |
| `runtime` | The four PEP endpoints only (`resolve-context`, `authorize`, `bulk-authorize`, `effective-permissions`) |
| `tenant:<id>` | Runtime + management restricted to a single tenant |

A key with `tenant:<id>` may pass the runtime *capability* check
(it's a runtime-eligible key) but every per-request call goes
through `enforce_tenant_scope_binding`, which compares the requested
tenant id against the scope. Wrong tenant → 403.

This protects against a tenant-scoped key probing other tenants by
crafting a clever `IdentityPrincipal` — even after `resolve-context`
maps it to a concrete tenant, the binding check refuses if the key
isn't authorized for that tenant.

## Issuing a key

```bash
curl -X POST http://localhost:8080/v1/api-keys \
  -H "X-API-Key: $BOOTSTRAP" \
  -d '{"name": "prod-runtime", "scopes": ["runtime"]}'
```

Response (single occurrence — store it now or roll a new one):

```json
{
  "id": "...",
  "name": "prod-runtime",
  "key_prefix": "azk_xxxx",
  "scopes": ["runtime"],
  "status": "active",
  "key": "azk_xxxxxx..."     // the plaintext, only on this response
}
```

Or via the SDK:

```python
material = admin.issue_api_key(name="prod-runtime", scopes=["runtime"])
print(material.key)   # the plaintext, save it now
```

The plaintext is returned exactly once. The DB stores the SHA-256 hash
plus a public-safe prefix you can include in logs.

## Rotation

```bash
curl -X POST http://localhost:8080/v1/api-keys/$KEY_ID/rotate \
  -H "X-API-Key: $BOOTSTRAP"
```

Rotation issues a *new* key with the same scopes and links it to the
old one via the `rotates` field for audit. Both keys remain valid
until you explicitly revoke the old one — do that after the consumers
have rolled to the new key.

```python
new_material = admin.rotate_api_key(old_id)
# … deploy new_material.key everywhere …
admin.revoke_api_key(old_id)
```

## Revocation

```bash
curl -X DELETE http://localhost:8080/v1/api-keys/$KEY_ID \
  -H "X-API-Key: $BOOTSTRAP"
```

Sets `status="revoked"`. Revoked keys never authenticate again.

## How the keys are stored

- Plaintext: `<prefix>_<32-byte URL-safe base64>` (≈48 chars total)
- Stored: SHA-256 hash + the 7-char public prefix + scopes (comma-joined)
- Comparison: hash lookup, then `hmac.compare_digest` to defeat timing attacks

Don't try to "validate" a key by reading the DB directly; let
`ApiKeyService` do it. It also bumps `last_used_at` on success so
you can spot stale keys.

## Headers

Either of these is accepted:

```http
X-API-Key: azk_xxxxxxxxxxxx
Authorization: Bearer azk_xxxxxxxxxxxx
```

Pick one in your callers and stick with it. Don't sprinkle both in
the same project.

## Avoiding self-lockout

A few practical rules:

- Always have at least one bootstrap key in `AUTHZ_API_KEYS` while
  you're operating with infrastructure. Treat it as the break-glass.
- Rotate-before-revoke. Never revoke before the new key is in service
  for every consumer.
- Run `authz inspect health` after rotation to confirm a fresh request
  succeeds with the new key.
- Keep the `key_prefix` in logs but never the full key; the hash makes
  full-key logs unrecoverable but they're still PII-grade leaky.

## See also

- `authzkit/security/api_keys.py` — `ApiKeyService`, scope checks
- `tests/integration/test_api_keys.py` — full lifecycle tests
- [Service & Deployment](service.md) — middleware, env vars
