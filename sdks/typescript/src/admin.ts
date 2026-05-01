/** Admin client for management operations. */

import {
  Agent,
  Application,
  Membership,
  Permission,
  Role,
  Tenant,
  agentFromWire,
  applicationFromWire,
  membershipFromWire,
  permissionFromWire,
  roleFromWire,
  tenantFromWire,
} from "./types.js";
import { AuthzClientError, AuthzServiceError } from "./errors.js";
import type { FetchFn } from "./client.js";

export interface AdminClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

export class AuthzAdminClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetchFn: FetchFn;
  private readonly timeoutMs: number;

  constructor(opts: AdminClientOptions) {
    if (!opts.baseUrl) throw new Error("AuthzAdminClient: baseUrl is required");
    this.baseUrl = opts.baseUrl.endsWith("/") ? opts.baseUrl : opts.baseUrl + "/";
    this.apiKey = opts.apiKey;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 10000;
  }

  private async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = this.baseUrl + path.replace(/^\//, "");
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchFn(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      if (response.status === 204) return undefined as T;
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
      if (e instanceof AuthzServiceError) throw e;
      throw new AuthzClientError(`transport error: ${String(e)}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  // ---- Tenants -----------------------------------------------------------

  async createTenant(opts: { slug: string; name: string; status?: string }): Promise<Tenant> {
    const data = await this.request<Record<string, unknown>>("POST", "v1/tenants", {
      slug: opts.slug,
      name: opts.name,
      status: opts.status ?? "active",
    });
    return tenantFromWire(data);
  }

  async getTenant(idOrSlug: string): Promise<Tenant> {
    const data = await this.request<Record<string, unknown>>("GET", `v1/tenants/${idOrSlug}`);
    return tenantFromWire(data);
  }

  async mapTenantExternal(
    tenantId: string,
    opts: { provider: string; issuer: string; externalTenantId: string },
  ): Promise<unknown> {
    return this.request("POST", `v1/tenants/${tenantId}/mappings`, {
      provider: opts.provider,
      issuer: opts.issuer,
      external_tenant_id: opts.externalTenantId,
    });
  }

  async setFeatureFlag(
    tenantId: string,
    opts: { key: string; value: unknown; applicationId?: string },
  ): Promise<unknown> {
    return this.request("PUT", `v1/tenants/${tenantId}/feature-flags`, {
      key: opts.key,
      value: opts.value,
      application_id: opts.applicationId ?? null,
    });
  }

  // ---- Applications ------------------------------------------------------

  async createApplication(opts: {
    slug: string;
    name: string;
    status?: string;
  }): Promise<Application> {
    const data = await this.request<Record<string, unknown>>("POST", "v1/applications", {
      slug: opts.slug,
      name: opts.name,
      status: opts.status ?? "active",
    });
    return applicationFromWire(data);
  }

  async getApplication(idOrSlug: string): Promise<Application> {
    const data = await this.request<Record<string, unknown>>(
      "GET",
      `v1/applications/${idOrSlug}`,
    );
    return applicationFromWire(data);
  }

  // ---- Roles & Permissions ----------------------------------------------

  async createRole(
    applicationId: string,
    opts: { name: string; scope?: string; description?: string },
  ): Promise<Role> {
    const data = await this.request<Record<string, unknown>>(
      "POST",
      `v1/applications/${applicationId}/roles`,
      {
        name: opts.name,
        scope: opts.scope ?? "application",
        description: opts.description ?? null,
      },
    );
    return roleFromWire(data);
  }

  async listRoles(applicationId: string): Promise<Role[]> {
    const rows = await this.request<Record<string, unknown>[]>(
      "GET",
      `v1/applications/${applicationId}/roles`,
    );
    return rows.map(roleFromWire);
  }

  async createPermission(
    applicationId: string,
    opts: { name: string; description?: string },
  ): Promise<Permission> {
    const data = await this.request<Record<string, unknown>>(
      "POST",
      `v1/applications/${applicationId}/permissions`,
      { name: opts.name, description: opts.description ?? null },
    );
    return permissionFromWire(data);
  }

  async listPermissions(applicationId: string): Promise<Permission[]> {
    const rows = await this.request<Record<string, unknown>[]>(
      "GET",
      `v1/applications/${applicationId}/permissions`,
    );
    return rows.map(permissionFromWire);
  }

  async setRolePermissions(roleId: string, permissions: string[]): Promise<unknown> {
    return this.request("PUT", `v1/roles/${roleId}/permissions`, { permissions });
  }

  // ---- Memberships ------------------------------------------------------

  async createMembership(
    tenantId: string,
    opts: {
      userId: string;
      applicationId?: string;
      roles?: string[];
      status?: string;
    },
  ): Promise<Membership> {
    const data = await this.request<Record<string, unknown>>(
      "POST",
      `v1/tenants/${tenantId}/memberships`,
      {
        user_id: opts.userId,
        application_id: opts.applicationId ?? null,
        roles: opts.roles ?? [],
        status: opts.status ?? "active",
      },
    );
    return membershipFromWire(data);
  }

  async listMemberships(
    tenantId: string,
    opts: { page?: number; pageSize?: number } = {},
  ): Promise<Membership[]> {
    const params = new URLSearchParams();
    params.set("page", String(opts.page ?? 1));
    params.set("page_size", String(opts.pageSize ?? 50));
    const rows = await this.request<Record<string, unknown>[]>(
      "GET",
      `v1/tenants/${tenantId}/memberships?${params.toString()}`,
    );
    return rows.map(membershipFromWire);
  }

  // ---- Agents -----------------------------------------------------------

  async createAgent(
    tenantId: string,
    applicationId: string,
    opts: { name: string; role?: string; status?: string },
  ): Promise<Agent> {
    const data = await this.request<Record<string, unknown>>(
      "POST",
      `v1/tenants/${tenantId}/applications/${applicationId}/agents`,
      {
        name: opts.name,
        role: opts.role ?? "",
        status: opts.status ?? "active",
      },
    );
    return agentFromWire(data);
  }

  async listAgents(tenantId: string, applicationId: string): Promise<Agent[]> {
    const rows = await this.request<Record<string, unknown>[]>(
      "GET",
      `v1/tenants/${tenantId}/applications/${applicationId}/agents`,
    );
    return rows.map(agentFromWire);
  }

  async setAgentRoles(agentId: string, roles: string[]): Promise<unknown> {
    return this.request("PUT", `v1/agents/${agentId}/roles`, { roles });
  }

  /** Find-or-create idempotent helper used by the bootstrap script. */
  async upsertRoleWithPermissions(
    applicationId: string,
    opts: { name: string; permissions: string[]; scope?: string; description?: string },
  ): Promise<Role> {
    const existing = (await this.listRoles(applicationId)).find((r) => r.name === opts.name);
    const role =
      existing ??
      (await this.createRole(applicationId, {
        name: opts.name,
        scope: opts.scope,
        description: opts.description,
      }));
    await this.setRolePermissions(role.id, opts.permissions);
    return role;
  }
}
