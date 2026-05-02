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
    PATH="/opt/venv/bin:$PATH"

# libpq for psycopg, curl for the HEALTHCHECK below. tini reaps zombie
# children when uvicorn forks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 authz \
    && useradd --system --uid 1000 --gid authz --create-home --shell /bin/bash authz

COPY --from=builder /opt/venv /opt/venv
COPY --chown=authz:authz authzkit /app/authzkit
COPY --chown=authz:authz authz_service /app/authz_service
COPY --chown=authz:authz authz_sdk /app/authz_sdk
COPY --chown=authz:authz migrations /app/migrations
COPY --chown=authz:authz alembic.ini /app/alembic.ini

WORKDIR /app
USER authz

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "authz_service.main:app", "--host", "0.0.0.0", "--port", "8080"]
