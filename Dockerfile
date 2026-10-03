FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY authzkit ./authzkit
COPY authz_service ./authz_service
COPY authz_sdk ./authz_sdk
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

# Build a wheel + install into a venv we can copy out — keeps the runtime
# layer free of the toolchain.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install .


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    AUTHZ_DATABASE_URL="sqlite+pysqlite:////data/authz.db" \
    AUTHZ_PORT=8080

# libpq for psycopg, curl for the HEALTHCHECK below. tini reaps zombie
# children when uvicorn forks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 authz \
    && useradd --system --uid 1000 --gid authz --create-home --shell /bin/bash authz \
    && mkdir -p /data \
    && chown authz:authz /data

COPY --from=builder /opt/venv /opt/venv
COPY --chown=authz:authz authzkit /app/authzkit
COPY --chown=authz:authz authz_service /app/authz_service
COPY --chown=authz:authz authz_sdk /app/authz_sdk
COPY --chown=authz:authz migrations /app/migrations
COPY --chown=authz:authz alembic.ini /app/alembic.ini
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Strip CRs in case the build context came from a Windows checkout with
# core.autocrlf=true; a CRLF shebang fails with "No such file or directory".
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod 0755 /usr/local/bin/docker-entrypoint.sh

WORKDIR /app
USER authz

# Default SQLite database lives here — mount a volume to keep data across
# container restarts. Point AUTHZ_DATABASE_URL at Postgres for production.
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs "http://localhost:${AUTHZ_PORT}/healthz" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["sh", "-c", "exec uvicorn authz_service.main:app --host 0.0.0.0 --port ${AUTHZ_PORT}"]
