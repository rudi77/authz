FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY authzkit ./authzkit
COPY authz_service ./authz_service
COPY authz_sdk ./authz_sdk
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

RUN pip install --upgrade pip \
    && pip install .

EXPOSE 8080

CMD ["uvicorn", "authz_service.main:app", "--host", "0.0.0.0", "--port", "8080"]
