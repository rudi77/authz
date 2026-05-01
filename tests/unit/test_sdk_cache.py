"""LRU + TTL behavior of the AuthzClient effective-permissions cache."""

from __future__ import annotations

import time

import httpx
import pytest

from authz_sdk.client import AuthzClient, Subject


class _StubTransport(httpx.BaseTransport):
    """Records every POST and returns a canned response.

    The SDK is sync so we must implement the sync transport API.
    """

    def __init__(self, response: dict) -> None:
        self.response = response
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        import json

        return httpx.Response(
            200,
            content=json.dumps(self.response),
            headers={"content-type": "application/json"},
        )


def _client(transport, **kwargs) -> AuthzClient:
    return AuthzClient(
        base_url="http://x",
        api_key="k",
        transport=transport,
        **kwargs,
    )


def test_cache_avoids_round_trip_within_ttl():
    transport = _StubTransport({"permissions": ["docs.read", "docs.write"]})
    client = _client(transport, cache_ttl_seconds=60.0)
    subject = Subject(type="user", user_id="u")

    for _ in range(3):
        perms = client.get_effective_permissions(
            tenant_id="t", application_id="a", subject=subject
        )
        assert perms == {"docs.read", "docs.write"}
    assert transport.calls == 1


def test_cache_eviction_when_exceeding_max_entries():
    transport = _StubTransport({"permissions": ["x"]})
    client = _client(transport, cache_ttl_seconds=60.0, cache_max_entries=2)
    for i in range(3):
        client.get_effective_permissions(
            tenant_id="t",
            application_id="a",
            subject=Subject(type="user", user_id=f"u{i}"),
        )
    # Three distinct subjects but cache holds only 2; the first should be evicted.
    assert len(client._cache) == 2


def test_bypass_cache_forces_fresh_call():
    transport = _StubTransport({"permissions": ["x"]})
    client = _client(transport, cache_ttl_seconds=60.0)
    subject = Subject(type="user", user_id="u")
    client.get_effective_permissions(tenant_id="t", application_id="a", subject=subject)
    client.get_effective_permissions(
        tenant_id="t", application_id="a", subject=subject, bypass_cache=True
    )
    assert transport.calls == 2


def test_invalidate_drops_partition():
    transport = _StubTransport({"permissions": ["x"]})
    client = _client(transport, cache_ttl_seconds=60.0)
    client.get_effective_permissions(
        tenant_id="t1", application_id="a", subject=Subject(type="user", user_id="u")
    )
    client.get_effective_permissions(
        tenant_id="t2", application_id="a", subject=Subject(type="user", user_id="u")
    )
    assert len(client._cache) == 2
    client.cache_invalidate(tenant_id="t1")
    assert len(client._cache) == 1
    keys = list(client._cache.keys())
    assert keys[0][0] == "t2"


def test_5xx_triggers_retry(monkeypatch):
    """A flaky upstream that recovers is retried up to the configured limit."""
    counter = {"calls": 0}

    class _Flaky(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            counter["calls"] += 1
            if counter["calls"] < 2:
                return httpx.Response(503, content=b"")
            import json

            return httpx.Response(
                200,
                content=json.dumps({"allowed": True, "decision": "allow", "reason": "ok",
                                     "required_permission": "x.y", "matched_permissions": []}),
                headers={"content-type": "application/json"},
            )

    client = AuthzClient(
        base_url="http://x",
        transport=_Flaky(),
        max_retries=2,
        retry_backoff_seconds=0.001,
    )
    allowed = client.authorize(
        tenant_id="t",
        application_id="a",
        subject=Subject(type="user", user_id="u"),
        resource="x",
        action="y",
    )
    assert allowed
    assert counter["calls"] == 2
