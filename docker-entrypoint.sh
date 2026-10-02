#!/bin/sh
# Container entrypoint for the authz service.
#
# AUTHZ_RUN_MIGRATIONS=true runs `alembic upgrade head` before the command, so
# a Postgres-backed container can start with a single `docker run`. SQLite
# (the default, stored under /data) is auto-created by the service itself.
set -e

if [ "${AUTHZ_RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "authz: applying database migrations (alembic upgrade head)"
    alembic upgrade head
fi

echo "authz: admin UI on http://localhost:${AUTHZ_PORT:-8080}/admin/"
exec "$@"
