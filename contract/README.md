# Contract-test fixture

A disposable authz for consumers' contract tests (first: Digital Teammates).
Test-only — the bootstrap key is public and the data lives in the container.

```bash
docker compose -f contract/docker-compose.contract.yml up --build -d
# … run your contract tests against http://localhost:18080 …
docker compose -f contract/docker-compose.contract.yml down
```

`up` runs three services:

| Service | What it does |
|---|---|
| `keygen` | Creates `contract/.secrets/signing-key.pem` once (RSA, PKCS#8). Kept across runs, so tokens and delegation grants keep the same `kid`. Put your own PEM there to pin a key. |
| `authz` | The service on SQLite (`/data`, fresh per container), OAuth Authorization Server on (`issuer = urn:authz:contract`), signing key from the file above, bootstrap operator key `contract-operator-key`. Published on `${AUTHZ_CONTRACT_PORT:-18080}`. |
| `seed` | Registers OAuth clients `dtm-management` (scope `admin`) and `dtm-runtime` (scope `runtime`), then lets the management client create application `dtm` via `PUT /v1/applications/dtm/catalog` — so `dtm` is **managed by** that client. Writes the credentials. Idempotent. |

`seed` exits 0 when done; wait for it with
`docker compose -f contract/docker-compose.contract.yml wait seed` (Compose ≥ 2.20)
or poll for `contract/.secrets/runtime.json`.

## Credentials

`contract/.secrets/` (gitignored):

- `management.json` — the manager of `dtm`: catalog, tenant state, tenant role overrides.
- `runtime.json` — decisions and delegation grants.

```json
{
  "client_id": "oc_…",
  "client_secret": "…",
  "scope": "admin",
  "base_url": "http://localhost:18080",
  "token_url": "http://localhost:18080/oauth/token",
  "application": "dtm"
}
```

Get a token with `client_credentials` (`client_secret_basic` or `client_secret_post`) and
send it as `Authorization: Bearer …`.

The operator key `contract-operator-key` is *not* the manager: writes to `dtm` with it get
`403 application_managed_externally` — which is what the consumer's tests should expect.

## Starting over

`down` removes the container and with it the database. If `seed` reports that `dtm` exists
but the credentials are stale (you deleted `.secrets` while the container was kept),
run `down` and `up` again. Delete `contract/.secrets/signing-key.pem` to rotate the key.

On Linux hosts the containers run as uid 1000; make `contract/` writable for that uid
(the files in `.secrets/` are created by it).

## Without Docker

```bash
python contract/keygen.py
AUTHZ_DATABASE_URL=sqlite+pysqlite:///./contract.db AUTHZ_API_KEYS=contract-operator-key \
AUTHZ_OAUTH_AS_ENABLED=true AUTHZ_OAUTH_ISSUER=urn:authz:contract \
AUTHZ_OAUTH_SIGNING_KEY_PEM="$(cat contract/.secrets/signing-key.pem)" \
  uvicorn authz_service.main:app --port 18080 &
python contract/seed.py --url http://localhost:18080 --admin-key contract-operator-key
```
