/** Local Policy Enforcement Points: ToolGuard + MCPGuard. */

import { PermissionDeniedError } from "./errors.js";
import { AuthzClient } from "./client.js";

export class ToolGuard {
  private readonly permissions: Set<string>;
  constructor(permissions: Iterable<string>) {
    this.permissions = new Set(permissions);
  }
  isAllowed(resource: string, action: string): boolean {
    return this.permissions.has(`${resource}.${action}`);
  }
  require(resource: string, action: string): void {
    if (!this.isAllowed(resource, action)) {
      throw new PermissionDeniedError(`${resource}.${action}`);
    }
  }
}

export class MCPGuard {
  private readonly permissions: Set<string>;
  constructor(permissions: Iterable<string>) {
    this.permissions = new Set(permissions);
  }
  isAllowed(server: string, action: string): boolean {
    return this.permissions.has(`mcp.${server}.${action}`);
  }
  require(server: string, action: string): void {
    if (!this.isAllowed(server, action)) {
      throw new PermissionDeniedError(`mcp.${server}.${action}`);
    }
  }
  allowedTools(server: string): string[] {
    const prefix = `mcp.${server}.`;
    return [...this.permissions]
      .filter((p) => p.startsWith(prefix))
      .map((p) => p.slice(prefix.length));
  }
}

/** Bundle: preload effective permissions and return guards bound to that snapshot. */
export async function startAgentSession(
  client: AuthzClient,
  opts: {
    tenantId: string;
    applicationId: string;
    userId: string;
    agentId: string;
  },
): Promise<{ tools: ToolGuard; mcp: MCPGuard; permissions: Set<string> }> {
  const permissions = await client.getEffectivePermissions({
    tenantId: opts.tenantId,
    applicationId: opts.applicationId,
    subject: { type: "agent", userId: opts.userId, agentId: opts.agentId },
  });
  return {
    tools: new ToolGuard(permissions),
    mcp: new MCPGuard(permissions),
    permissions,
  };
}
