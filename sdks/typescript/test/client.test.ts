import { test } from "node:test";
import assert from "node:assert/strict";

import { AuthzClient } from "../src/client.js";
import { ToolGuard, MCPGuard, startAgentSession } from "../src/guard.js";
import { AuthzServiceError, PermissionDeniedError } from "../src/errors.js";

/**
 * Minimal mock of the global fetch function. Each invocation increments a
 * counter so tests can assert on retry / cache behavior, and the handler
 * decides what to return based on the request URL + body.
 */
function makeMockFetch(
  handler: (url: string, init?: RequestInit) => { status: number; body: unknown },
): { fetch: typeof fetch; calls: () => number } {
  let calls = 0;
  const mock: typeof fetch = async (input, init) => {
    calls++;
    const url = typeof input === "string" ? input : input.toString();
    const { status, body } = handler(url, init);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch: mock, calls: () => calls };
}

test("authorize returns allow result", async () => {
  const { fetch } = makeMockFetch(() => ({
    status: 200,
    body: {
      allowed: true,
      decision: "allow",
      reason: "permission_granted",
      required_permission: "docs.read",
      matched_permissions: ["docs.read"],
    },
  }));
  const client = new AuthzClient({ baseUrl: "http://x", apiKey: "k", fetchFn: fetch });
  const result = await client.authorize({
    tenantId: "t",
    applicationId: "a",
    subject: { type: "user", userId: "u" },
    resource: "docs",
    action: "read",
  });
  assert.equal(result.allowed, true);
  assert.equal(result.requiredPermission, "docs.read");
});

test("require throws PermissionDeniedError when denied", async () => {
  const { fetch } = makeMockFetch(() => ({
    status: 200,
    body: {
      allowed: false,
      decision: "deny",
      reason: "missing_permission",
      required_permission: "docs.write",
      matched_permissions: [],
    },
  }));
  const client = new AuthzClient({ baseUrl: "http://x", fetchFn: fetch });
  await assert.rejects(
    () =>
      client.require({
        tenantId: "t",
        applicationId: "a",
        subject: { type: "user", userId: "u" },
        resource: "docs",
        action: "write",
      }),
    (err: unknown) => err instanceof PermissionDeniedError,
  );
});

test("getEffectivePermissions caches by subject", async () => {
  const { fetch, calls } = makeMockFetch(() => ({
    status: 200,
    body: { permissions: ["docs.read", "tools.gmail.send"] },
  }));
  const client = new AuthzClient({
    baseUrl: "http://x",
    fetchFn: fetch,
    cacheTtlMs: 60_000,
  });
  for (let i = 0; i < 3; i++) {
    const perms = await client.getEffectivePermissions({
      tenantId: "t",
      applicationId: "a",
      subject: { type: "user", userId: "u" },
    });
    assert.ok(perms.has("docs.read"));
  }
  assert.equal(calls(), 1, "expected single round-trip thanks to LRU cache");
});

test("post retries on 5xx", async () => {
  let attempt = 0;
  const fetch: typeof globalThis.fetch = async () => {
    attempt++;
    if (attempt === 1) {
      return new Response("boom", { status: 500 });
    }
    return new Response(
      JSON.stringify({ allowed: true, decision: "allow", reason: "ok", required_permission: "x.y", matched_permissions: [] }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  const client = new AuthzClient({
    baseUrl: "http://x",
    fetchFn: fetch,
    maxRetries: 2,
    retryBackoffMs: 1,
  });
  const result = await client.authorize({
    tenantId: "t",
    applicationId: "a",
    subject: { type: "user", userId: "u" },
    resource: "x",
    action: "y",
  });
  assert.equal(result.allowed, true);
  assert.equal(attempt, 2);
});

test("4xx surfaces AuthzServiceError without retry", async () => {
  let calls = 0;
  const fetch: typeof globalThis.fetch = async () => {
    calls++;
    return new Response(JSON.stringify({ error: "missing_or_invalid_api_key" }), {
      status: 401,
    });
  };
  const client = new AuthzClient({
    baseUrl: "http://x",
    fetchFn: fetch,
    maxRetries: 3,
    retryBackoffMs: 1,
  });
  await assert.rejects(
    () =>
      client.authorize({
        tenantId: "t",
        applicationId: "a",
        subject: { type: "user", userId: "u" },
        resource: "x",
        action: "y",
      }),
    (err: unknown) =>
      err instanceof AuthzServiceError && err.status === 401,
  );
  assert.equal(calls, 1, "4xx should not be retried");
});

test("ToolGuard.require throws on missing permission", () => {
  const guard = new ToolGuard(["docs.read"]);
  assert.throws(() => guard.require("docs", "write"), PermissionDeniedError);
  assert.doesNotThrow(() => guard.require("docs", "read"));
});

test("MCPGuard reports allowed tools per server", () => {
  const guard = new MCPGuard(["mcp.github.read_repo", "mcp.github.create_issue"]);
  assert.deepEqual(guard.allowedTools("github").sort(), ["create_issue", "read_repo"]);
  assert.equal(guard.isAllowed("slack", "send"), false);
});

test("startAgentSession yields working guards", async () => {
  const { fetch } = makeMockFetch(() => ({
    status: 200,
    body: { permissions: ["docs.read", "mcp.github.read_repo"] },
  }));
  const client = new AuthzClient({ baseUrl: "http://x", fetchFn: fetch });
  const session = await startAgentSession(client, {
    tenantId: "t",
    applicationId: "a",
    userId: "u",
    agentId: "agent",
  });
  assert.ok(session.tools.isAllowed("docs", "read"));
  assert.ok(session.mcp.isAllowed("github", "read_repo"));
  assert.equal(session.mcp.isAllowed("github", "create_issue"), false);
});
