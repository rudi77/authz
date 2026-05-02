# Load tests

Two equivalent harnesses; pick whichever fits your workflow:

- **`asyncio_load.py`** — single-file Python script. Zero deps beyond
  httpx. Reports p50/p95/p99 + throughput in <30s.
- **`locustfile.py`** — locust scenario covering all four runtime
  endpoints with a realistic traffic mix.

## Quick start

```bash
# 1. Bring up the service
docker compose up -d

# 2. Bootstrap a tenant + app + role
authz bootstrap --spec examples/bootstrap.example.yaml

# 3. Pick a user via the resolve-context call (or the admin UI), then:
export AUTHZ_BASE_URL=http://localhost:8080
export AUTHZ_API_KEY=dev-key
export AUTHZ_TENANT_ID=<...>
export AUTHZ_APPLICATION_ID=<...>
export AUTHZ_USER_ID=<...>

# 4a. Asyncio sanity sweep
python loadtests/asyncio_load.py --concurrency 50 --requests 5000

# 4b. Locust UI
pip install locust
locust -f loadtests/locustfile.py --host=$AUTHZ_BASE_URL
```

## Reference numbers (laptop, SQLite)

Indicative only — Postgres + tuned pool will be higher. Latency target
on a single uvicorn worker: **<10 ms p95** for ``/v1/authorize`` after
warm-up. With cached effective-permissions on the SDK side, runtime
checks should not bottleneck downstream services up to ~5k req/s.

## Production tuning checklist

1. Run multiple uvicorn workers behind a reverse proxy (gunicorn or
   uvicorn-workers).
2. Enable Redis-backed rate-limit + idempotency (set ``AUTHZ_REDIS_URL``).
3. Tune SQLAlchemy pool: ``AUTHZ_DATABASE_POOL_SIZE`` env var (TODO).
4. Turn on Prometheus scraping at ``/metrics``; wire alerting on
   ``authz_decisions_denied_total`` spikes and p95 latency.
5. Enable OpenTelemetry (``AUTHZ_OTEL_ENABLED=true``) for tail-latency
   investigations.
