"""Cross-cutting middleware: rate limiting, idempotency keys.

Both pieces have an in-memory backend (single-process) and a Redis backend
(multi-process). The factories at the bottom pick the backend based on
``Settings.redis_url``; tests pin the in-memory backend explicitly.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any, Protocol

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


# ----------------------------------------------------------------------------
# Rate limit
# ----------------------------------------------------------------------------


class RateLimiter(Protocol):
    limit: int

    def allow(self, key: str) -> tuple[bool, int, float]: ...


class _SlidingWindowLimiter:
    """In-memory per-key rolling window. Single-process."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}

    def allow(self, key: str) -> tuple[bool, int, float]:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket
            cutoff = now - self.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = max(0.001, bucket[0] + self.window - now)
                return False, 0, retry_after
            bucket.append(now)
            return True, self.limit - len(bucket), 0.0


class _RedisRateLimiter:
    """Redis-backed sliding-window limiter using sorted sets.

    Uses the ZSET of timestamps + ZREMRANGEBYSCORE pattern so the window
    is computed atomically per request.
    """

    _SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window_ms = tonumber(ARGV[2])
    local limit = tonumber(ARGV[3])
    redis.call('ZREMRANGEBYSCORE', key, 0, now - window_ms)
    local count = redis.call('ZCARD', key)
    if count >= limit then
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local retry_after_ms = (tonumber(oldest[2]) + window_ms) - now
        return {0, 0, retry_after_ms}
    end
    redis.call('ZADD', key, now, now .. '-' .. math.random())
    redis.call('PEXPIRE', key, window_ms)
    return {1, limit - count - 1, 0}
    """

    def __init__(self, redis_client, limit: int, window_seconds: float, *, key_prefix: str = "authz:rl") -> None:
        self.limit = limit
        self.window_ms = int(window_seconds * 1000)
        self._client = redis_client
        self._key_prefix = key_prefix
        self._script = redis_client.register_script(self._SCRIPT)

    def allow(self, key: str) -> tuple[bool, int, float]:
        now_ms = int(time.time() * 1000)
        result = self._script(
            keys=[f"{self._key_prefix}:{key}"],
            args=[now_ms, self.window_ms, self.limit],
        )
        allowed_flag, remaining, retry_after_ms = result
        return bool(int(allowed_flag)), int(remaining), max(0.0, int(retry_after_ms) / 1000.0)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-API-key sliding-window rate limit.

    Disabled when ``limit`` is 0. The backend is plug-and-play.
    """

    def __init__(self, app, *, limit_per_minute: int, limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        self._enabled = limit_per_minute > 0
        if not self._enabled:
            self._limiter = None
        else:
            self._limiter = limiter or _SlidingWindowLimiter(limit_per_minute, 60.0)

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        if not self._enabled or self._limiter is None:
            return await call_next(request)
        key = (
            request.headers.get("X-API-Key")
            or (request.client.host if request.client else None)
            or "anonymous"
        )
        allowed, remaining, retry_after = self._limiter.allow(key)
        if not allowed:
            response = JSONResponse(
                {"error": "rate_limited", "retry_after": retry_after},
                status_code=429,
            )
            response.headers["Retry-After"] = f"{retry_after:.0f}"
            return response
        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self._limiter.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


# ----------------------------------------------------------------------------
# Idempotency
# ----------------------------------------------------------------------------


class IdempotencyStore(Protocol):
    def get(self, key: str) -> tuple[int, bytes, str] | None: ...
    def put(self, key: str, status: int, body: bytes, content_type: str, ttl_seconds: float) -> None: ...


class _MemoryIdempotencyStore:
    def __init__(self, max_entries: int = 1024) -> None:
        self._max = max_entries
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[int, bytes, str, float]] = {}

    def get(self, key: str) -> tuple[int, bytes, str] | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            status, body, content_type, expires_at = entry
            if expires_at <= time.monotonic():
                self._cache.pop(key, None)
                return None
            return status, body, content_type

    def put(self, key: str, status: int, body: bytes, content_type: str, ttl_seconds: float) -> None:
        with self._lock:
            self._cache[key] = (status, body, content_type, time.monotonic() + ttl_seconds)
            while len(self._cache) > self._max:
                oldest = min(self._cache.items(), key=lambda kv: kv[1][3])
                self._cache.pop(oldest[0], None)


class _RedisIdempotencyStore:
    """Stores status + content-type + body as a Redis hash, expired via PEXPIRE."""

    def __init__(self, redis_client, *, key_prefix: str = "authz:idem") -> None:
        self._client = redis_client
        self._key_prefix = key_prefix

    def _full_key(self, key: str) -> str:
        return f"{self._key_prefix}:{key}"

    def get(self, key: str) -> tuple[int, bytes, str] | None:
        data = self._client.hgetall(self._full_key(key))
        if not data:
            return None
        # redis-py returns bytes by default
        status = int(data.get(b"status", b"0").decode("utf-8"))
        body = data.get(b"body", b"")
        ct = data.get(b"content_type", b"application/json").decode("utf-8")
        return status, body, ct

    def put(self, key: str, status: int, body: bytes, content_type: str, ttl_seconds: float) -> None:
        full = self._full_key(key)
        self._client.hset(full, mapping={
            "status": str(status),
            "body": body,
            "content_type": content_type,
        })
        self._client.pexpire(full, int(ttl_seconds * 1000))


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Replays the first response for repeated POSTs sharing an Idempotency-Key."""

    def __init__(
        self,
        app,
        *,
        ttl_seconds: float = 300.0,
        store: IdempotencyStore | None = None,
    ) -> None:
        super().__init__(app)
        self._ttl = ttl_seconds
        self._store = store or _MemoryIdempotencyStore()

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        if request.method != "POST":
            return await call_next(request)
        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            return await call_next(request)
        api_key = request.headers.get("X-API-Key", "")
        cache_key = f"{api_key}:{request.url.path}:{idempotency_key}"

        cached = self._store.get(cache_key)
        if cached is not None:
            status, body, content_type = cached
            return Response(
                content=body,
                status_code=status,
                media_type=content_type,
                headers={"Idempotent-Replay": "true"},
            )

        response: Response = await call_next(request)
        if 200 <= response.status_code < 500:
            body_chunks = [chunk async for chunk in response.body_iterator]
            body = b"".join(body_chunks)

            async def _replay():
                yield body

            response.body_iterator = _replay()  # type: ignore[assignment]
            content_type = response.headers.get("content-type", "application/json")
            self._store.put(cache_key, response.status_code, body, content_type, self._ttl)
        return response


# ----------------------------------------------------------------------------
# Pagination helpers
# ----------------------------------------------------------------------------


def paginate_params(page: int = 1, page_size: int = 50) -> tuple[int, int]:
    """Validate pagination inputs and return (offset, limit)."""
    page = max(1, page)
    page_size = max(1, min(500, page_size))
    return (page - 1) * page_size, page_size


# ----------------------------------------------------------------------------
# Backend factories
# ----------------------------------------------------------------------------


def build_rate_limiter(limit_per_minute: int, redis_url: str | None) -> RateLimiter | None:
    """Pick the rate limiter backend based on settings."""
    if limit_per_minute <= 0:
        return None
    if not redis_url:
        return _SlidingWindowLimiter(limit_per_minute, 60.0)
    try:
        import redis  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        return _SlidingWindowLimiter(limit_per_minute, 60.0)
    client = redis.Redis.from_url(redis_url)
    return _RedisRateLimiter(client, limit_per_minute, 60.0)


def build_idempotency_store(redis_url: str | None) -> IdempotencyStore:
    if not redis_url:
        return _MemoryIdempotencyStore()
    try:
        import redis  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        return _MemoryIdempotencyStore()
    client = redis.Redis.from_url(redis_url)
    return _RedisIdempotencyStore(client)
