# Deploying authz for a consumer (Digital Teammates)

How to run authz in production next to an application that uses it as its
permission authority — first consumer: Digital Teammates (DTM). The
reference stack is [`docker-compose.yml`](docker-compose.yml) in this
directory; [`verify.py`](verify.py) runs the whole first start below
against a throwaway copy of it.

## Image

```
ghcr.io/rudi77/authz:<tag>
```

| Tag | Built from |
|---|---|
| `vX.Y.Z` | release tag `vX.Y.Z` — **pin this in production** |
| `latest`, `<git sha>` | every push to `main` |

CI (`.github/workflows/ci.yml`) builds, smoke-tests and pushes the image. If
the package is private, `docker login ghcr.io` with a token that has
`read:packages`. The image runs as uid 1000 behind `tini`, listens on
`:8080`, and has a `HEALTHCHECK` on `/healthz`.

## The stack

`docker-compose.yml` (project name `authz`):

| Service | What |
|---|---|
| `authz-db` | Postgres 16, volume `authz_pgdata` — the only state |
| `authz` | the service; `AUTHZ_RUN_MIGRATIONS=true` runs `alembic upgrade head` on every start (idempotent); healthcheck `/healthz` |
| `authz-redis` | only with `--profile ha` (more than one replica) |

No host port: the consumer reaches `http://authz:8080` on the Docker network
`authz` (name configurable with `AUTHZ_NETWORK`). A consumer in another
Compose project joins it as an external network:

```yaml
# consumer's docker-compose.yml
services:
  runtime:
    networks: [default, authz]
networks:
  authz:
    external: true
    name: authz
```

Or copy the two services into the consumer's own Compose file (DTM: the
`authz` profile of `deploy/docker-compose.yml`, which still needs the
environment below — its `DATABASE_URL` alone is not enough).

## Environment

Set in the shell or in `deploy/.env` (gitignored; Compose reads it
automatically):

| Variable | Required | Meaning |
|---|---|---|
| `AUTHZ_IMAGE` | — | default `ghcr.io/rudi77/authz:latest`; pin `ghcr.io/rudi77/authz:vX.Y.Z` |
| `AUTHZ_POSTGRES_PASSWORD` | yes | password of the `authz` database user |
| `AUTHZ_BOOTSTRAP_API_KEY` | yes | break-glass operator key (admin scope) → `AUTHZ_API_KEYS` |
| `AUTHZ_OAUTH_ISSUER` | yes | `iss` of the tokens and delegation grants this authz signs, e.g. `https://authz.example.com` |
| `AUTHZ_SIGNING_KEY_FILE` | — | host path of the signing key, default `./secrets/signing-key.pem` |
| `AUTHZ_REDIS_URL` | with `--profile ha` | `redis://authz-redis:6379/0` |
| `AUTHZ_RATE_LIMIT_PER_MINUTE` | — | default `0` (off) |
| `AUTHZ_AUDIT_RETENTION_DAYS` | — | default `90` |
| `AUTHZ_LOG_LEVEL` | — | default `INFO` |
| `AUTHZ_NETWORK` | — | default `authz` |

What the Compose file sets in the container (when you run the image another
way, set these yourself):

| Container variable | Value | Why |
|---|---|---|
| `AUTHZ_DATABASE_URL` | `postgresql+psycopg://authz:…@authz-db:5432/authz` | Postgres; SQLite is the image default |
| `AUTHZ_RUN_MIGRATIONS` | `true` | the service never changes a Postgres schema on its own |
| `AUTHZ_API_KEYS` | the bootstrap key | without any key every request is rejected (fail-closed) |
| `AUTHZ_OAUTH_AS_ENABLED` | `true` | `client_credentials` tokens for the consumer |
| `AUTHZ_OAUTH_ISSUER` | as above | required when the AS is on (startup fails otherwise) |
| `AUTHZ_OAUTH_SIGNING_KEY_PEM_FILE` | `/run/secrets/authz_signing_key` | the entrypoint loads it into `AUTHZ_OAUTH_SIGNING_KEY_PEM`. On Postgres there is no auto-generated key: without one, `/oauth/token` fails and `POST /v1/delegations` answers `503 signing_key_unavailable` |

Do not set `AUTHZ_DEV_MODE` and do not set `AUTHZ_CORS_ORIGINS=*`
(see [SECURITY.md](../SECURITY.md), production checklist).

## First start

All commands from the repository root (or wherever this directory lives).

1. **Signing key** (RSA-2048, PKCS#8 PEM), once:

   ```bash
   mkdir -p deploy/secrets
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out deploy/secrets/signing-key.pem
   chmod 0444 deploy/secrets/signing-key.pem   # readable by the container's uid 1000
   ```

   Without openssl: `docker run --rm --entrypoint python ghcr.io/rudi77/authz:<tag> -c "…"`
   with the snippet `KEYGEN` from `verify.py`. Keep the file in your secret
   store; every replica needs the same key. Alternative without a file:
   `docker compose -f deploy/docker-compose.yml exec authz authz oauth signing-key generate`
   stores a key in Postgres (fallback; see SECURITY.md on key custody).

2. **Start** — migrations run in the entrypoint before the service starts:

   ```bash
   docker compose -f deploy/docker-compose.yml up -d --wait
   docker compose -f deploy/docker-compose.yml logs authz | grep "applying database migrations"
   ```

3. **Bootstrap credential.** `AUTHZ_BOOTSTRAP_API_KEY` is the operator's
   admin key (`X-API-Key`). Keep it for setup and emergencies; the consumer
   never gets it.

4. **Clients for the consumer** — the CLI talks to the database directly,
   no API key needed. Each secret is printed once:

   ```bash
   docker compose -f deploy/docker-compose.yml exec authz \
     authz oauth client create --name dtm-management --scopes admin
   docker compose -f deploy/docker-compose.yml exec authz \
     authz oauth client create --name dtm-runtime --scopes runtime
   ```

   - `dtm-management` (scope `admin`) becomes the **manager** of application
     `dtm`: the first `PUT /v1/applications/dtm/catalog` it sends creates the
     application with `managed_by = client:<its client_id>`. From then on
     only it writes permissions, roles, memberships, agents and tenant state
     of `dtm`; everyone else (the operator key included) gets
     `403 application_managed_externally`. If `dtm` already exists without a
     manager, the client takes it over with
     `POST /v1/applications/dtm/claim-management`.
   - `dtm-runtime` (scope `runtime`) asks for decisions
     (`/v1/authorize`, `/v1/bulk-authorize`, `/v1/effective-permissions`) and
     issues delegation grants.

   Rotate a secret with `authz oauth client rotate <client_id>`, revoke with
   `authz oauth client revoke <client_id>`.

5. **Hand over to DTM** (configuration section `Authz`; as environment
   variables with `__`):

   | DTM setting | Value |
   |---|---|
   | `Authz:BaseUrl` | URL of authz as DTM reaches it (see TLS below) |
   | `Authz:ApplicationSlug` | `dtm` |
   | `Authz:IdentityIssuer` | issuer of DTM's user references, e.g. `urn:dtm:<installation>` |
   | `Authz:Runtime:ClientId` / `Authz:Runtime:ClientSecret` | from `dtm-runtime` |
   | `Authz:Management:ClientId` / `Authz:Management:ClientSecret` | from `dtm-management` |

   DTM gets tokens from `<BaseUrl>/oauth/token` (`client_credentials`,
   `client_secret_basic` or `client_secret_post`).

6. **Check** — `python deploy/verify.py` repeats steps 1–4 on a throwaway
   project and drives the API the way DTM does (see below).

### TLS

authz speaks plain HTTP. DTM requires an `https` `Authz:BaseUrl` in the
`Production` environment, so put a TLS-terminating proxy in front of authz
(e.g. a route in DTM's Caddy) and give DTM that URL. Plain
`http://authz:8080` on the internal network only passes DTM's validation
outside `Production`.

## Verifying a deployment

```bash
python deploy/verify.py                                     # builds the image from this checkout
python deploy/verify.py --image ghcr.io/rudi77/authz:vX.Y.Z  # checks a published image
python deploy/verify.py --keep                              # leaves the stack running
```

Standard library only; needs Docker with Compose v2. It uses its own Compose
project `authz-verify` (own network, own volume, random passwords, a fresh
signing key under `deploy/secrets/`) and removes everything afterwards.
Checks: migrations ran from the entrypoint; both clients created with the
CLI get tokens; the management client's catalog PUT makes it `managed_by`;
tenant state PUT; `/v1/authorize` with `user_ref` and `agent_name` (and a
deny for an unknown user); a delegation grant is issued (signing key on
Postgres) and accepted; runtime client and operator key get 403 on the
managed catalog. Exit code 0 when everything passed.

## Running more than one replica

- **authz is stateless.** Everything durable — tenants, applications,
  OAuth clients, API keys, delegation grants, admin sessions, audit — lives
  in Postgres. Back up Postgres; nothing else.
- **Redis** for the per-request shared state: with `AUTHZ_REDIS_URL` the
  rate-limit counters and idempotency keys are shared; without it each
  replica counts on its own (N replicas = N × the limit) and a replayed
  idempotent request can land on a replica that has not seen it. Start with
  `--profile ha` and `AUTHZ_REDIS_URL=redis://authz-redis:6379/0`.
- **Same signing key on every replica** (the same secret file). Each
  process caches its key; after a rotation restart the replicas.
- **Migrations once per release:** with several replicas, let one instance
  (or a one-off `docker compose run --rm authz alembic upgrade head`) migrate
  and start the others with `AUTHZ_RUN_MIGRATIONS=false`.
- Background janitors (audit retention, expired sessions, retiring signing
  keys) run on every replica; their deletes are idempotent.
- Scale with `docker compose -f deploy/docker-compose.yml up -d --scale authz=3`
  (no host port, so no port clash); Docker DNS spreads `authz` across them.
