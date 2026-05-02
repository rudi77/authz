/**
 * Runtime AuthzClient — thin wrapper over the AuthZ service's runtime endpoints.
 *
 * Includes a bounded LRU cache keyed by (tenant, app, subject) so an agent
 * runtime can preload effective permissions at the start of a session and
 * avoid round-trips for every tool call.
 */

import {
  AuthorizeResult,
  BulkCheck,
  BulkCheckResult,
  ResolvedContext,
  Subject,
  authorizeResultFromWire,
  resolvedContextFromWire,
  subjectToWire,
} from "./types.js";
import { AuthzClientError, AuthzServiceError, PermissionDeniedError } from "./errors.js";

/** Fetch-compatible interface — lets tests inject a mock without touching globals. */
export type FetchFn = typeof fetch;

export interface AuthzClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  /** Cache TTL in ms. 0 disables caching. */
  cacheTtlMs?: number;
  cacheMaxEntries?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
}

interface CacheEntry {
  permissions: Set<string>;
  expiresAt: number;
}

export class AuthzClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetchFn: FetchFn;
  private readonly timeoutMs: number;
  private readonly cacheTtl: number;
  private readonly cacheMax: number;
  private readonly maxRetries: number;
  private readonly retryBackoffMs: number;
  private readonly cache: Map<string, CacheEntry> = new Map();

  constructor(opts: AuthzClientOptions) {
    if (!opts.baseUrl) throw new Error("AuthzClient: baseUrl is required");
    this.baseUrl = opts.baseUrl.endsWith("/") ? opts.baseUrl : opts.baseUrl + "/";
    this.apiKey = opts.apiKey;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.cacheTtl = opts.cacheTtlMs ?? 0;
    this.cacheMax = opts.cacheMaxEntries ?? 1024;
    this.maxRetries = opts.maxRetries ?? 2;
    this.retryBackoffMs = opts.retryBackoffMs ?? 100;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = this.baseUrl + path.replace(/^\//, "");
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;

    let attempt = 0;
    let lastErr: unknown = null;
    while (attempt <= this.maxRetries) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await this.fetchFn(url, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        clearTimeout(timeout);

        if (response.status >= 500 && attempt < this.maxRetries) {
          attempt++;
          await sleep(this.retryBackoffMs * 2 ** (attempt - 1));
          continue;
        }
        if (response.status >= 400) {
          let detail: unknown;
          try {
            detail = await response.json();
          } catch {
            detail = await response.text();
          }
          throw new AuthzServiceError(response.status, detail);
        }
        return (await response.json()) as T;
      } catch (e) {
        clearTimeout(timeout);
        if (e instanceof AuthzServiceError) throw e;
        lastErr = e;
        attempt++;
        if (attempt > this.maxRetries) break;
        await sleep(this.retryBackoffMs * 2 ** (attempt - 1));
      }
    }
    throw new AuthzClientError(`transport error after retries: ${String(lastErr)}`);
  }

  // -------------------------------------------------------------------------

  async resolveContext(opts: {
    applicationId: string;
    provider: string;
    issuer: string;
    subject: string;
    email?: string;
    externalTenantId?: string;
    explicitTenantId?: string;
    claims?: Record<string, unknown>;
  }): Promise<ResolvedContext> {
    const data = await this.post<Record<string, unknown>>("v1/resolve-context", {
      application_id: opts.applicationId,
      provider: opts.provider,
      issuer: opts.issuer,
      subject: opts.subject,
      email: opts.email,
      external_tenant_id: opts.externalTenantId,
      explicit_tenant_id: opts.explicitTenantId,
      claims: opts.claims ?? {},
    });
    return resolvedContextFromWire(data);
  }

  async authorize(opts: {
    tenantId: string;
    applicationId: string;
    subject: Subject;
    resource: string;
    action: string;
    context?: Record<string, unknown>;
  }): Promise<AuthorizeResult> {
    const data = await this.post<Record<string, unknown>>("v1/authorize", {
      tenant_id: opts.tenantId,
      application_id: opts.applicationId,
      subject: subjectToWire(opts.subject),
      resource: opts.resource,
      action: opts.action,
      context: opts.context ?? {},
    });
    return authorizeResultFromWire(data);
  }

  async require(opts: {
    tenantId: string;
    applicationId: string;
    subject: Subject;
    resource: string;
    action: string;
    context?: Record<string, unknown>;
  }): Promise<void> {
    const result = await this.authorize(opts);
    if (!result.allowed) {
      throw new PermissionDeniedError(result.requiredPermission);
    }
  }

  async bulkAuthorize(opts: {
    tenantId: string;
    applicationId: string;
    subject: Subject;
    checks: BulkCheck[];
    context?: Record<string, unknown>;
  }): Promise<BulkCheckResult[]> {
    const data = await this.post<{ results: Record<string, unknown>[] }>(
      "v1/bulk-authorize",
      {
        tenant_id: opts.tenantId,
        application_id: opts.applicationId,
        subject: subjectToWire(opts.subject),
        checks: opts.checks.map((c) => ({ resource: c.resource, action: c.action })),
        context: opts.context ?? {},
      },
    );
    return data.results.map((r) => ({
      resource: r.resource as string,
      action: r.action as string,
      allowed: !!r.allowed,
      reason: (r.reason as string) ?? "",
    }));
  }

  async getEffectivePermissions(opts: {
    tenantId: string;
    applicationId: string;
    subject: Subject;
    bypassCache?: boolean;
  }): Promise<Set<string>> {
    const cacheKey = `${opts.tenantId}|${opts.applicationId}|${opts.subject.type}|${opts.subject.userId ?? ""}|${opts.subject.agentId ?? ""}`;
    if (this.cacheTtl > 0 && !opts.bypassCache) {
      const cached = this.cache.get(cacheKey);
      if (cached && cached.expiresAt > Date.now()) {
        // Move-to-end for LRU semantics: delete + re-insert.
        this.cache.delete(cacheKey);
        this.cache.set(cacheKey, cached);
        return new Set(cached.permissions);
      }
      this.cache.delete(cacheKey);
    }
    const data = await this.post<{ permissions: string[] }>(
      "v1/effective-permissions",
      {
        tenant_id: opts.tenantId,
        application_id: opts.applicationId,
        subject: subjectToWire(opts.subject),
      },
    );
    const permissions = new Set(data.permissions ?? []);
    if (this.cacheTtl > 0) {
      this.cache.set(cacheKey, {
        permissions: new Set(permissions),
        expiresAt: Date.now() + this.cacheTtl,
      });
      while (this.cache.size > this.cacheMax) {
        const oldest = this.cache.keys().next().value;
        if (oldest === undefined) break;
        this.cache.delete(oldest);
      }
    }
    return permissions;
  }

  cacheInvalidate(opts: { tenantId?: string; applicationId?: string } = {}): void {
    for (const key of [...this.cache.keys()]) {
      const [t, a] = key.split("|");
      if (
        (opts.tenantId === undefined || t === opts.tenantId) &&
        (opts.applicationId === undefined || a === opts.applicationId)
      ) {
        this.cache.delete(key);
      }
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
