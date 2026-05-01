"""Cross-cutting middleware: rate limiting, idempotency keys.

Both pieces use in-memory state by default. For multi-process deployments,
swap the backing stores for Redis (the interfaces below are intentionally
small enough to make that drop-in).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class _SlidingWindowLimiter:
    """Per-API-key rolling window. Acceptable for single-process deployments.

    Each caller gets a deque of recent request timestamps; when adding a new
    one, anything older than the window expires. Trade-off: O(n) per request
    in the worst case, but n is bounded by the per-window quota.
    """

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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limit by API key (X-API-Key) with a per-minute cap.

    Disabled when ``limit`` is 0 — relevant in tests and dev.
    """

    def __init__(self, app, *, limit_per_minute: int) -> None:
        super().__init__(app)
        self._enabled = limit_per_minute > 0
        self._limiter = _SlidingWindowLimiter(limit_per_minute, 60.0)

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        if not self._enabled:
            return await call_next(request)
        # Tie the bucket to the API key. Anonymous callers (dev mode) share
        # one bucket — rate limiting is most useful when keys are configured.
        key = request.headers.get("X-API-Key") or request.client.host or "anonymous"
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


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Honor ``Idempotency-Key`` headers on POST requests.

    Caches the first response (status + body) for ``ttl_seconds`` and
    replays it for repeated calls with the same key. The cache key is scoped
    by API key + path + idempotency key so two callers can't collide.
    """

    def __init__(self, app, *, ttl_seconds: float = 300.0, max_entries: int = 1024) -> None:
        super().__init__(app)
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str, str], tuple[int, bytes, str, float]] = {}

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        if request.method != "POST":
            return await call_next(request)
        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            return await call_next(request)
        api_key = request.headers.get("X-API-Key", "")
        cache_key = (api_key, request.url.path, idempotency_key)

        with self._lock:
            entry = self._cache.get(cache_key)
            if entry is not None:
                status, body, content_type, expires_at = entry
                if expires_at > time.monotonic():
                    return Response(
                        content=body,
                        status_code=status,
                        media_type=content_type,
                        headers={"Idempotent-Replay": "true"},
                    )
                self._cache.pop(cache_key, None)

        response: Response = await call_next(request)
        # Only cache 2xx and 4xx; 5xx is a transient state callers should retry.
        if 200 <= response.status_code < 500:
            body_chunks = [chunk async for chunk in response.body_iterator]
            body = b"".join(body_chunks)

            async def _replay():
                yield body

            response.body_iterator = _replay()  # type: ignore[assignment]
            content_type = response.headers.get("content-type", "application/json")
            with self._lock:
                self._cache[cache_key] = (
                    response.status_code,
                    body,
                    content_type,
                    time.monotonic() + self._ttl,
                )
                while len(self._cache) > self._max_entries:
                    # Evict the entry with the earliest expiration.
                    oldest = min(self._cache.items(), key=lambda kv: kv[1][3])
                    self._cache.pop(oldest[0], None)
        return response


# ---- Pagination helpers -----------------------------------------------------


def paginate_params(page: int = 1, page_size: int = 50) -> tuple[int, int]:
    """Validate pagination inputs and return (offset, limit)."""
    page = max(1, page)
    page_size = max(1, min(500, page_size))
    return (page - 1) * page_size, page_size
