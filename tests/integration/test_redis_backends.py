"""Redis-backed rate limit + idempotency smoke tests.

Skipped when ``AUTHZ_TEST_REDIS_URL`` is not set; CI sets it via the
docker-compose service when wanted. Uses ``fakeredis`` as a fallback so
the test still exercises the redis-py interface even without a running
Redis instance.
"""

from __future__ import annotations

import os
import time

import pytest


def _get_redis_client():
    url = os.environ.get("AUTHZ_TEST_REDIS_URL")
    if url:
        try:
            import redis  # type: ignore[import-not-found]
        except ImportError:
            pytest.skip("redis package not installed")
        return redis.Redis.from_url(url)
    try:
        import fakeredis  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("neither AUTHZ_TEST_REDIS_URL nor fakeredis available")
    return fakeredis.FakeRedis()


def test_redis_rate_limiter_enforces_window():
    client = _get_redis_client()
    # fakeredis lacks Lua/EVAL support depending on version; skip in that case
    # so the meaningful Redis-backed-store test below still runs.
    try:
        client.eval("return 1", 0)
    except Exception:
        pytest.skip("redis client does not support Lua scripts")

    from authz_service.middleware import _RedisRateLimiter

    limiter = _RedisRateLimiter(client, limit=2, window_seconds=60.0)
    key = f"test-{time.time()}"
    allowed1, _, _ = limiter.allow(key)
    allowed2, _, _ = limiter.allow(key)
    allowed3, _, retry = limiter.allow(key)
    assert allowed1
    assert allowed2
    assert not allowed3
    assert retry > 0


def test_redis_idempotency_store_round_trip():
    client = _get_redis_client()
    from authz_service.middleware import _RedisIdempotencyStore

    store = _RedisIdempotencyStore(client, key_prefix=f"itest:{time.time()}")
    assert store.get("k1") is None
    store.put("k1", 201, b'{"ok":true}', "application/json", 10.0)
    cached = store.get("k1")
    assert cached is not None
    status, body, ct = cached
    assert status == 201
    assert body == b'{"ok":true}'
    assert ct == "application/json"
