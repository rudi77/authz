#!/bin/sh
# Container entrypoint for the authz service.
#
# AUTHZ_RUN_MIGRATIONS=true runs `alembic upgrade head` before the command, so
# a Postgres-backed container can start with a single `docker run`. SQLite
# (the default, stored under /data) is auto-created by the service itself.
set -e

# AUTHZ_OAUTH_SIGNING_KEY_PEM_FILE: read the (multi-line) signing key from a
# file, e.g. a docker / Kubernetes secret, so it never sits in the environment
# definition. An explicitly set AUTHZ_OAUTH_SIGNING_KEY_PEM wins.
if [ -n "${AUTHZ_OAUTH_SIGNING_KEY_PEM_FILE:-}" ] && [ -z "${AUTHZ_OAUTH_SIGNING_KEY_PEM:-}" ]; then
    AUTHZ_OAUTH_SIGNING_KEY_PEM="$(cat "$AUTHZ_OAUTH_SIGNING_KEY_PEM_FILE")"
    export AUTHZ_OAUTH_SIGNING_KEY_PEM
fi

if [ "${AUTHZ_RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "authz: applying database migrations (alembic upgrade head)"
    alembic upgrade head
fi

echo "authz: admin UI on http://localhost:${AUTHZ_PORT:-8080}/admin/"
exec "$@"
