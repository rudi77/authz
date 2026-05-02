"""Asyncio-based load test for the runtime endpoints.

Use when locust feels heavyweight — this is a single Python process that
fires N concurrent requests over M iterations and reports p50/p95/p99
latency plus throughput. Sufficient for laptop-sanity-checking the
service after a change.

Usage::

    AUTHZ_BASE_URL=http://localhost:8080 AUTHZ_API_KEY=dev-key \\
    AUTHZ_TENANT_ID=... AUTHZ_APPLICATION_ID=... AUTHZ_USER_ID=... \\
        python loadtests/asyncio_load.py --concurrency 50 --requests 5000
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from statistics import median, quantiles

import httpx


async def run_request(client: httpx.AsyncClient, payload: dict) -> tuple[float, int]:
    start = time.perf_counter()
    response = await client.post("/v1/authorize", json=payload)
    return time.perf_counter() - start, response.status_code


async def worker(
    client: httpx.AsyncClient,
    payload: dict,
    iterations: int,
    timings: list[float],
    statuses: dict[int, int],
) -> None:
    for _ in range(iterations):
        elapsed, status = await run_request(client, payload)
        timings.append(elapsed)
        statuses[status] = statuses.get(status, 0) + 1


async def main_async(args: argparse.Namespace) -> None:
    base = os.environ.get("AUTHZ_BASE_URL", "http://localhost:8080")
    api_key = os.environ.get("AUTHZ_API_KEY", "dev-key")
    tenant_id = os.environ["AUTHZ_TENANT_ID"]
    application_id = os.environ["AUTHZ_APPLICATION_ID"]
    user_id = os.environ["AUTHZ_USER_ID"]

    payload = {
        "tenant_id": tenant_id,
        "application_id": application_id,
        "subject": {"type": "user", "user_id": user_id},
        "resource": args.resource,
        "action": args.action,
    }

    iterations_per_worker = args.requests // args.concurrency
    timings: list[float] = []
    statuses: dict[int, int] = {}

    headers = {"X-API-Key": api_key}
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    async with httpx.AsyncClient(base_url=base, headers=headers, limits=limits, timeout=10.0) as client:
        wall_start = time.perf_counter()
        await asyncio.gather(
            *[
                worker(client, payload, iterations_per_worker, timings, statuses)
                for _ in range(args.concurrency)
            ]
        )
        wall_elapsed = time.perf_counter() - wall_start

    if not timings:
        print("no timings collected")
        return
    timings.sort()
    p50 = median(timings)
    qs = quantiles(timings, n=100)
    p95 = qs[94]
    p99 = qs[98]
    print("=" * 64)
    print(f"requests       : {len(timings)}")
    print(f"concurrency    : {args.concurrency}")
    print(f"wall time      : {wall_elapsed:.2f}s")
    print(f"throughput     : {len(timings) / wall_elapsed:.1f} req/s")
    print(f"latency p50    : {p50 * 1000:.2f} ms")
    print(f"latency p95    : {p95 * 1000:.2f} ms")
    print(f"latency p99    : {p99 * 1000:.2f} ms")
    print(f"status codes   : {statuses}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--resource", default="docs")
    parser.add_argument("--action", default="read")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
